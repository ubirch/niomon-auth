package com.ubirch.messageauth

import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64

import com.typesafe.config.ConfigFactory
import com.ubirch.messageauth.AuthCheckers.CheckResult
import com.ubirch.niomon.base.{NioMicroservice, NioMicroserviceMock}
import com.ubirch.niomon.util.EnrichedMap.toEnrichedMap
import org.apache.kafka.clients.producer.ProducerRecord
import com.ubirch.kafka.RichAnyProducerRecord
import org.apache.kafka.common.serialization.{ByteArraySerializer, StringDeserializer}
import org.nustaq.serialization.FSTConfiguration
import org.redisson.codec.FstCodec
import org.scalatest.{BeforeAndAfterAll, FlatSpec, Matchers}

import scala.concurrent.TimeoutException
import scala.concurrent.duration._

//noinspection TypeAnnotation
class MessageAuthTest extends FlatSpec with Matchers with BeforeAndAfterAll {
  implicit val bytesSerializer = new ByteArraySerializer
  implicit val stringDeserializer = new StringDeserializer

  // TODO: figure out what to do with redis in tests - run an embedded server?
  val context = new NioMicroservice.Context(???, ConfigFactory.load().getConfig("niomon-auth"))

  // ignored by default, because requires username and password to be passed in through env variables
  "checkCumulocity" should "authorize with basic auth passed in" ignore {
    val username = System.getenv("TEST_USERNAME")
    val password = System.getenv("TEST_PASSWORD")
    val basicAuth = s"Basic ${Base64.getEncoder.encodeToString(s"$username:$password".getBytes(UTF_8))}"

    new AuthCheckers(context).checkCumulocity(Map("Authorization" -> basicAuth)).isAuthPassed should equal (true)
  }

  // our cumulocity tenant doesn't yet support logging in through OAuth, so this is disabled
  it should "authorize with oauth tokens passed via cookie" ignore {
    val oauthToken = System.getenv("TEST_OAUTH_TOKEN")
    val xsrfToken = System.getenv("TEST_XSRF_TOKEN")
    val headers = Map("X-XSRF-TOKEN" -> xsrfToken, "Cookie" -> s"authorization=$oauthToken")

    new AuthCheckers(context).checkCumulocity(headers).isAuthPassed should equal (true)
  }

  // ignored by default, because it does an external request
  "checkUbirch" should "authorize with device id and password passed in" ignore {
    val deviceId = "55424952-3c71-bf80-26dc-3c71bf8026dc"
    val password = "MDAwMjY5MmItNGRkYy00MDAzLWJhNjEtNTQ0ZDViODRjZTlm"

    val res = new AuthCheckers(context).checkUbirch(Map(
      "X-Ubirch-Hardware-Id" -> deviceId,
      "X-Ubirch-Credential" -> password
    ))

    res.isAuthPassed should equal (true)
    res.headersToAdd should have size (1)
    res.headersToAdd.keys should contain ("X-Ubirch-DeviceInfo-Token")
  }

  it should "fail when device id is missing" in {
    val password = "MDAwMjY5MmItNGRkYy00MDAzLWJhNjEtNTQ0ZDViODRjZTlm"

    val res = new AuthCheckers(context).checkUbirch(Map(
      "X-Ubirch-Credential" -> password
    ))

    res.isAuthPassed should equal (false)
    res.headersToAdd should have size (0)
    res.rejectionReason.get.getMessage should include ("X-Ubirch-Hardware-Id")
  }

  it should "fail when password is missing" in {
    val deviceId = "55424952-3c71-bf80-26dc-3c71bf8026dc"

    val res = new AuthCheckers(context).checkUbirch(Map(
      "X-Ubirch-Hardware-Id".toLowerCase -> deviceId
    ))

    res.isAuthPassed should equal (false)
    res.headersToAdd should have size (0)
    res.rejectionReason.get.getMessage should include ("X-Ubirch-Credential")
  }

  // ignored by default, because it does an external request
  "checkTokenUbirch" should "authorize with device id and token passed in" ignore {
    val deviceId = "55424952-3c71-bf80-26dc-3c71bf8026dc"
    val token = "MDAwMjY5MmItNGRkYy00MDAzLWJhNjEtNTQ0ZDViODRjZTlm"

    val res = new AuthCheckers(context).checkUbirchToken(Map(
      "X-Ubirch-Hardware-Id" -> deviceId,
      "X-Ubirch-Credential" -> token
    ))

    res.isAuthPassed should equal (true)
    res.headersToAdd should have size (1)
    res.headersToAdd.keys should contain ("X-Ubirch-DeviceInfo-Token")
  }

  it should "fail when device id is missing" in {
    val token = "MDAwMjY5MmItNGRkYy00MDAzLWJhNjEtNTQ0ZDViODRjZTlm"

    val res = new AuthCheckers(context).checkUbirchToken(Map(
      "X-Ubirch-Credential" -> token
    ))

    res.isAuthPassed should equal (false)
    res.headersToAdd should have size (0)
    res.rejectionReason.get.getMessage should include ("X-Ubirch-Hardware-Id")
  }

  it should "fail when token is missing" in {
    val deviceId = "55424952-3c71-bf80-26dc-3c71bf8026dc"

    val res = new AuthCheckers(context).checkUbirchToken(Map(
      "X-Ubirch-Hardware-Id".toLowerCase -> deviceId
    ))

    res.isAuthPassed should equal (false)
    res.headersToAdd should have size (0)
    res.rejectionReason.get.getMessage should include ("X-Ubirch-Credential")
  }

  "authFlow" should "direct messages to authorized topic if authorized" in {
    val microservice = messageAuthMicroservice(new AuthCheckers(_).alwaysAccept)
    microservice.outputTopics = Map("authorized" -> "auth", "unauthorized" -> "unauth")
    import microservice.kafkaMocks._

    publishToKafka(arbitraryRecordWithHeaders("input", "X-Please-Let-Me-Pass" -> "true"))
    publishToKafka(arbitraryRecordWithHeaders("input", "X-Foo" -> "foo"))
    publishToKafka(arbitraryRecordWithHeaders("input", "X-Bar" -> "bar"))

    val authorized = consumeNumberStringMessagesFrom("auth", 3)

    // assert no pending messages on unauthorized topic
    a[TimeoutException] should be thrownBy {
      consumeNumberMessagesFromTopics[String](Set("unauth"), 1, timeout = 1.second)
    }

    authorized.size should equal(3)
  }

  it should "direct messages to unauthorized topic if unauthorized" in {
    val microservice = messageAuthMicroservice(new AuthCheckers(_).alwaysReject)
    microservice.outputTopics = Map("authorized" -> "auth", "unauthorized" -> "unauth")
    import microservice.kafkaMocks._

    publishToKafka(arbitraryRecordWithHeaders("input", "X-Please-Let-Me-Pass" -> "true"))
    publishToKafka(arbitraryRecordWithHeaders("input", "X-Foo" -> "foo"))
    publishToKafka(arbitraryRecordWithHeaders("input", "X-Bar" -> "bar"))

    val unauthorized = consumeNumberStringMessagesFrom("unauth", 3)

    // assert no pending messages on authorized topic
    a[TimeoutException] should be thrownBy {
      consumeNumberMessagesFromTopics[String](Set("auth"), 1, timeout = 1.second)
    }

    unauthorized.size should equal(3)
  }

  it should "direct messages according to passed AuthChecker" in {
    val microservice = messageAuthMicroservice(_ => { headers =>
      AuthCheckers.boolToArbitraryRejectionCheckResult(headers.CaseInsensitive.get("X-Must-Be-Even").exists(_.toInt % 2 == 0))
    })
    microservice.outputTopics = Map("authorized" -> "auth", "unauthorized" -> "unauth")
    import microservice.kafkaMocks._

    publishToKafka(arbitraryRecordWithHeaders("input", "X-Must-Be-Even" -> "0"))
    publishToKafka(arbitraryRecordWithHeaders("input", "X-Must-Be-Even" -> "1"))
    publishToKafka(arbitraryRecordWithHeaders("input", "X-Must-Be-Even" -> "2"))

    val authorized = consumeNumberStringMessagesFrom("auth", 2)
    val unauthorized = consumeNumberStringMessagesFrom("unauth", 1)

    authorized.size should equal(2)
    unauthorized.size should equal(1)
  }

  "CheckResult" should "be serializable and deserializable by the serializer we use in redisson" in {
    val codec = new FstCodec(FSTConfiguration.createDefaultConfiguration().setForceSerializable(true))
    val passedCheck = AuthCheckers.boolToArbitraryRejectionCheckResult(true)
    val failedCheck = AuthCheckers.boolToArbitraryRejectionCheckResult(false)

    val passedEncoded = codec.getValueEncoder.encode(passedCheck)
    val failedEncoded = codec.getValueEncoder.encode(failedCheck)

    val passedDecoded = codec.getValueDecoder.decode(passedEncoded, null).asInstanceOf[CheckResult]
    val failedDecoded = codec.getValueDecoder.decode(failedEncoded, null).asInstanceOf[CheckResult]

    passedDecoded should equal (passedCheck)
//    failedDecoded should equal (failedCheck) // exceptions don't do equals well
    failedDecoded.isAuthPassed should equal (false)
    failedDecoded.headersToAdd should equal (Map())
    failedDecoded.rejectionReason.get.getMessage should equal ("arbitrary rejection")
  }

  private def messageAuthMicroservice(checkerFactory: NioMicroservice.Context => AuthCheckers.AuthChecker) =
    NioMicroserviceMock(MessageAuthMicroservice(checkerFactory))

  private def arbitraryRecordWithHeaders(topic: String, headers: (String, String)*): ProducerRecord[String, Array[Byte]] =
    new ProducerRecord[String, Array[Byte]](topic, "value".getBytes(UTF_8)).withHeaders(headers : _ *)

}
