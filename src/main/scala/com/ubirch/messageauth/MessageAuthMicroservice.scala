package com.ubirch.messageauth

import com.typesafe.config.Config
import com.ubirch.niomon.base.NioMicroservice
import com.ubirch.kafka._
import com.ubirch.messageauth.AuthCheckers.AuthChecker
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.kafka.clients.producer.ProducerRecord

class MessageAuthMicroservice(authCheckerFactory: Config => AuthChecker) extends NioMicroservice[Array[Byte], Array[Byte]]("message-auth") {
  val checkAuth: AuthChecker = authCheckerFactory(config)
  val authorizedTopic: String = outputTopics("authorized")
  val unauthorizedTopic: String = outputTopics("unauthorized")

  override def processRecord(record: ConsumerRecord[String, Array[Byte]]): ProducerRecord[String, Array[Byte]] = {
    val headers = record.headersScala
    val authPassed = checkAuth(headers)

    if (authPassed) {
      logger.debug(s"request with key [${record.key()}] is authorized")
      record.toProducerRecord(authorizedTopic)
    } else {
      logger.debug(s"request with key [${record.key()}] is NOT authorized")
      record.toProducerRecord(unauthorizedTopic).withExtraHeaders("http-status-code" -> "401")
    }
  }
}
