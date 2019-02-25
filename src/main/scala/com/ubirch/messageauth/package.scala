package com.ubirch

import akka.NotUsed
import akka.actor.ActorSystem
import akka.kafka.{ConsumerMessage, ProducerMessage, _}
import akka.kafka.scaladsl.{Consumer, Producer}
import akka.stream.scaladsl.{Flow, Keep, RestartSink, RestartSource, RunnableGraph, Sink, Source}
import akka.stream.{ActorMaterializer, KillSwitches, UniqueKillSwitch}
import com.typesafe.config.{Config, ConfigFactory}
import com.typesafe.scalalogging.StrictLogging
import com.ubirch.kafka._
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.common.serialization.{ByteArrayDeserializer, ByteArraySerializer, StringDeserializer, StringSerializer}

import scala.concurrent.ExecutionContextExecutor
import scala.concurrent.duration._

package object messageauth extends StrictLogging {
  val conf: Config = ConfigFactory.load
  implicit val system: ActorSystem = ActorSystem("message-auth")
  implicit val materializer: ActorMaterializer = ActorMaterializer()
  implicit val executionContext: ExecutionContextExecutor = system.dispatcher

  private val kafkaUrl: String = conf.getString("kafka.url")

  val producerConfig: Config = system.settings.config.getConfig("akka.kafka.producer")
  val producerSettings: ProducerSettings[String, Array[Byte]] =
    ProducerSettings(producerConfig, new StringSerializer, new ByteArraySerializer)
      .withBootstrapServers(kafkaUrl)

  val consumerConfig: Config = system.settings.config.getConfig("akka.kafka.consumer")
  val consumerSettings: ConsumerSettings[String, Array[Byte]] =
    ConsumerSettings(consumerConfig, new StringDeserializer, new ByteArrayDeserializer)
      .withBootstrapServers(kafkaUrl)
      .withGroupId("message-auth")
      .withProperty(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")

  val incomingTopic: String = conf.getString("kafka.topic.incoming")
  val authorizedTopic: String = conf.getString("kafka.topic.authorized")
  val unauthorizedTopic: String = conf.getString("kafka.topic.unauthorized")

  val kafkaSource: Source[ConsumerMessage.CommittableMessage[String, Array[Byte]], NotUsed] =
    RestartSource.withBackoff(
      minBackoff = 2.seconds,
      maxBackoff = 1.minute,
      randomFactor = 0.2
    ) { () => Consumer.committableSource(consumerSettings, Subscriptions.topics(incomingTopic)) }

  val kafkaSink: Sink[ProducerMessage.Envelope[String, Array[Byte], ConsumerMessage.Committable], NotUsed] =
    RestartSink.withBackoff(
      minBackoff = 2.seconds,
      maxBackoff = 1.minute,
      randomFactor = 0.2
    ) { () => Producer.commitableSink(producerSettings) }

  type AuthChecker = Map[String, String] => Boolean
  val checkAuth: AuthChecker = AuthCheckers.get(conf.getString("checkingStrategy"))

  type FlowIn = ConsumerMessage.CommittableMessage[String, Array[Byte]]
  type FlowOut = ProducerMessage.Message[String, Array[Byte], ConsumerMessage.CommittableOffset]

  def authFlow(authChecker: AuthChecker): Flow[FlowIn, FlowOut, NotUsed] =
    Flow[ConsumerMessage.CommittableMessage[String, Array[Byte]]].map { msg =>
      val record = msg.record
      val headers = record.headersScala
      val authPassed = authChecker(headers)

      val outgoingRecord = if (authPassed) {
        logger.debug(s"request with key [${record.key()}] is authorized")
        record.toProducerRecord(authorizedTopic)
      } else {
        logger.debug(s"request with key [${record.key()}] is NOT authorized")
        record.toProducerRecord(unauthorizedTopic).withExtraHeaders("http-status-code" -> "401")
      }

      ProducerMessage.Message(outgoingRecord, msg.committableOffset)
  }

  def authGraph(authChecker: AuthChecker): RunnableGraph[UniqueKillSwitch] =
    kafkaSource.viaMat(KillSwitches.single)(Keep.right).via(authFlow(authChecker)).to(kafkaSink)
}
