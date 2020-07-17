package com.ubirch.messageauth

import com.ubirch.kafka._
import com.ubirch.messageauth.AuthCheckers.{AuthChecker, CheckResult}
import com.ubirch.niomon.base.{NioMicroservice, NioMicroserviceLogic}
import net.logstash.logback.argument.StructuredArguments.v
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.kafka.clients.producer.ProducerRecord

class MessageAuthMicroservice(authCheckerFactory: NioMicroservice.Context => AuthChecker, runtime: NioMicroservice[Array[Byte], Array[Byte]])
  extends NioMicroserviceLogic[Array[Byte], Array[Byte]](runtime) {
  val checkAuth: AuthChecker = authCheckerFactory(context)
  val authorizedTopic: String = outputTopics("authorized")
  val unauthorizedTopic: String = outputTopics("unauthorized")

  def processRecord(record: ConsumerRecord[String, Array[Byte]]): ProducerRecord[String, Array[Byte]] = {

    val requestId = record.requestIdHeader().orNull

    val CheckResult(rejectionReason, headersToAdd) = checkAuth(record.headersScala)

    rejectionReason match {
      case None =>
        logger.info(s"request [{}] is authorized", v("requestId", requestId))
        record.toProducerRecord(authorizedTopic).withExtraHeaders(headersToAdd.toSeq: _*)
      case Some(reason) =>
        logger.info(s"request [{}] is NOT authorized; reason: {}", v("requestId", requestId),
          v("notAuthorizedReason", reason.getMessage))
        record.toProducerRecord(unauthorizedTopic).withExtraHeaders("http-status-code" -> "401")
    }
  }
}

object MessageAuthMicroservice {
  def apply(authCheckerFactory: NioMicroservice.Context => AuthChecker)
           (runtime: NioMicroservice[Array[Byte], Array[Byte]]): MessageAuthMicroservice =
    new MessageAuthMicroservice(authCheckerFactory, runtime)
}
