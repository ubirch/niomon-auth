package com.ubirch.messageauth

import com.ubirch.kafka._
import com.ubirch.messageauth.AuthCheckers.AuthChecker
import com.ubirch.niomon.base.{NioMicroservice, NioMicroserviceLogic}
import net.logstash.logback.argument.StructuredArguments.v
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.kafka.clients.producer.ProducerRecord

class MessageAuthMicroservice(authCheckerFactory: NioMicroservice.Context => AuthChecker, runtime: NioMicroservice[Array[Byte], Array[Byte]])
  extends NioMicroserviceLogic[Array[Byte], Array[Byte]](runtime) {
  val checkAuth: AuthChecker = authCheckerFactory(context)
  val authorizedTopic: String = outputTopics("authorized")
  val unauthorizedTopic: String = outputTopics("unauthorized")

  override def processRecord(record: ConsumerRecord[String, Array[Byte]]): ProducerRecord[String, Array[Byte]] = {
    val headers = record.headersScala
    val authPassed = checkAuth(headers)

    if (authPassed) {
      logger.debug(s"request with key [${v("requestId", record.key())}] is authorized")
      record.toProducerRecord(authorizedTopic)
    } else {
      logger.debug(s"request with key [${v("requestId", record.key())}] is NOT authorized")
      record.toProducerRecord(unauthorizedTopic).withExtraHeaders("http-status-code" -> "401")
    }
  }
}

object MessageAuthMicroservice {
  def apply(authCheckerFactory: NioMicroservice.Context => AuthChecker)
    (runtime: NioMicroservice[Array[Byte], Array[Byte]]): MessageAuthMicroservice =
    new MessageAuthMicroservice(authCheckerFactory, runtime)
}
