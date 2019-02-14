package com.ubirch

import akka.NotUsed
import akka.actor.ActorSystem
import akka.kafka.{ConsumerMessage, ProducerMessage, _}
import akka.kafka.scaladsl.{Consumer, Producer}
import akka.stream.scaladsl.{Flow, Keep, RestartSink, RestartSource, RunnableGraph, Sink, Source}
import akka.stream.{ActorMaterializer, KillSwitches, UniqueKillSwitch}
import com.typesafe.config.{Config, ConfigFactory}
import com.typesafe.scalalogging.StrictLogging
import com.ubirch.kafka.{EnvelopeDeserializer, EnvelopeSerializer, MessageEnvelope}
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.common.serialization.{StringDeserializer, StringSerializer}

import scala.concurrent.ExecutionContextExecutor
import scala.concurrent.duration._

package object messageauth extends StrictLogging {
  val conf: Config = ConfigFactory.load
  implicit val system: ActorSystem = ActorSystem("message-auth")
  implicit val materializer: ActorMaterializer = ActorMaterializer()
  implicit val executionContext: ExecutionContextExecutor = system.dispatcher

  private val kafkaUrl: String = conf.getString("kafka.url")

  val producerConfig: Config = system.settings.config.getConfig("akka.kafka.producer")
  val producerSettings: ProducerSettings[String, MessageEnvelope] =
    ProducerSettings(producerConfig, new StringSerializer, EnvelopeSerializer)
      .withBootstrapServers(kafkaUrl)

  val consumerConfig: Config = system.settings.config.getConfig("akka.kafka.consumer")
  val consumerSettings: ConsumerSettings[String, MessageEnvelope] =
    ConsumerSettings(consumerConfig, new StringDeserializer, EnvelopeDeserializer)
      .withBootstrapServers(kafkaUrl)
      .withGroupId("message-auth")
      .withProperty(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")

  val incomingTopic: String = conf.getString("kafka.topic.incoming")
  val authorizedTopic: String = conf.getString("kafka.topic.authorized")
  val unauthorizedTopic: String = conf.getString("kafka.topic.unauthorized")

  val kafkaSource: Source[ConsumerMessage.CommittableMessage[String, MessageEnvelope], NotUsed] =
    RestartSource.withBackoff(
      minBackoff = 2.seconds,
      maxBackoff = 1.minute,
      randomFactor = 0.2
    ) { () => Consumer.committableSource(consumerSettings, Subscriptions.topics(incomingTopic)) }

  val kafkaSink: Sink[ProducerMessage.Envelope[String, MessageEnvelope, ConsumerMessage.Committable], NotUsed] =
    RestartSink.withBackoff(
      minBackoff = 2.seconds,
      maxBackoff = 1.minute,
      randomFactor = 0.2
    ) { () => Producer.commitableSink(producerSettings) }

  type AuthChecker = Map[String, String] => Boolean
  val checkAuth: AuthChecker = AuthCheckers.get(conf.getString("checkingStrategy"))

  private type FlowIn = ConsumerMessage.CommittableMessage[String, MessageEnvelope]
  private type FlowOut = ProducerMessage.Message[String, MessageEnvelope, ConsumerMessage.CommittableOffset]

  def authFlow(authChecker: AuthChecker): Flow[FlowIn, FlowOut, NotUsed] =
    Flow[ConsumerMessage.CommittableMessage[String, MessageEnvelope]].map { msg =>
      val record = msg.record
      val headers = record.headersScala
      val authPassed = authChecker(headers)

      val targetTopic = if (authPassed) authorizedTopic else unauthorizedTopic
      val outgoingRecord = record.toProducerRecord(targetTopic)

      ProducerMessage.Message(outgoingRecord, msg.committableOffset)
  }

  def authGraph(authChecker: AuthChecker): RunnableGraph[UniqueKillSwitch] =
    kafkaSource.viaMat(KillSwitches.single)(Keep.right).via(authFlow(authChecker)).to(kafkaSink)
}
