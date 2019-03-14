package com.ubirch.messageauth

import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64

import com.typesafe.config.ConfigFactory
import net.manub.embeddedkafka.EmbeddedKafka
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.header.Header
import org.apache.kafka.common.header.internals.RecordHeader
import org.apache.kafka.common.serialization.{ByteArraySerializer, StringDeserializer}
import org.scalatest.{FlatSpec, Matchers}

import scala.collection.JavaConverters._
import scala.concurrent.duration._
import scala.concurrent.{Await, Awaitable, TimeoutException}

//noinspection TypeAnnotation
class MessageAuthTest extends FlatSpec with Matchers with EmbeddedKafka {
  implicit val bytesSerializer = new ByteArraySerializer
  implicit val stringDeserializer = new StringDeserializer
  val config = ConfigFactory.load().getConfig("message-auth")

  // ignored by default, because requires username and password to be passed in through env variables
  "checkCumulocity" should "authorize with basic auth passed in" ignore {
    val username = System.getenv("TEST_USERNAME")
    val password = System.getenv("TEST_PASSWORD")
    val basicAuth = s"Basic ${Base64.getEncoder.encodeToString(s"$username:$password".getBytes(UTF_8))}"

    new AuthCheckers(config).checkCumulocity(Map("Authorization" -> basicAuth)) should equal(true)
  }

  // our cumulocity tenant doesn't yet support logging in through OAuth, so this is disabled
  it should "authorize with oauth tokens passed via cookie" ignore {
    val oauthToken = System.getenv("TEST_OAUTH_TOKEN")
    val xsrfToken = System.getenv("TEST_XSRF_TOKEN")
    val headers = Map("X-XSRF-TOKEN" -> xsrfToken, "Cookie" -> s"authorization=$oauthToken")

    new AuthCheckers(config).checkCumulocity(headers) should equal(true)
  }

  "authFlow" should "direct messages to authorized topic if authorized" in {
    withRunningKafka {
      val microservice = new MessageAuthMicroservice(new AuthCheckers(_).alwaysAccept)
      val control = microservice.run

      val input = microservice.inputTopics.head
      publishToKafka(arbitraryRecordWithHeaders(input, "X-Please-Let-Me-Pass" -> "true"))
      publishToKafka(arbitraryRecordWithHeaders(input, "X-Foo" -> "foo"))
      publishToKafka(arbitraryRecordWithHeaders(input, "X-Bar" -> "bar"))

      val authorized = consumeNumberStringMessagesFrom(microservice.authorizedTopic, 3)

      // assert no pending messages on unauthorized topic
      a[TimeoutException] should be thrownBy {
        consumeNumberMessagesFromTopics[String](Set(microservice.unauthorizedTopic), 1, timeout = 1.second)
      }

      authorized.size should equal(3)

      await(control.drainAndShutdown()(microservice.system.dispatcher))
    }
  }

  it should "direct messages to unauthorized topic if unauthorized" in {
    withRunningKafka {
      val microservice = new MessageAuthMicroservice(new AuthCheckers(_).alwaysReject)
      val control = microservice.run

      val input = microservice.inputTopics.head
      publishToKafka(arbitraryRecordWithHeaders(input, "X-Please-Let-Me-Pass" -> "true"))
      publishToKafka(arbitraryRecordWithHeaders(input, "X-Foo" -> "foo"))
      publishToKafka(arbitraryRecordWithHeaders(input, "X-Bar" -> "bar"))

      val unauthorized = consumeNumberStringMessagesFrom(microservice.unauthorizedTopic, 3)

      // assert no pending messages on authorized topic
      a[TimeoutException] should be thrownBy {
        consumeNumberMessagesFromTopics[String](Set(microservice.authorizedTopic), 1, timeout = 1.second)
      }

      unauthorized.size should equal(3)
      await(control.drainAndShutdown()(microservice.system.dispatcher))
    }
  }

  it should "direct messages according to passed AuthChecker" in {
    withRunningKafka {
      val microservice = new MessageAuthMicroservice(_ => { headers => headers.get("X-Must-Be-Even").exists(_.toInt % 2 == 0) })
      val control = microservice.run

      val input = microservice.inputTopics.head
      publishToKafka(arbitraryRecordWithHeaders(input, "X-Must-Be-Even" -> "0"))
      publishToKafka(arbitraryRecordWithHeaders(input, "X-Must-Be-Even" -> "1"))
      publishToKafka(arbitraryRecordWithHeaders(input, "X-Must-Be-Even" -> "2"))

      val authorized = consumeNumberStringMessagesFrom(microservice.authorizedTopic, 2)
      val unauthorized = consumeNumberStringMessagesFrom(microservice.unauthorizedTopic, 1)

      authorized.size should equal (2)
      unauthorized.size should equal (1)

      await(control.drainAndShutdown()(microservice.system.dispatcher))
    }
  }

  private def arbitraryRecordWithHeaders(topic: String, headers: (String, String)*): ProducerRecord[String, Array[Byte]] =
    new ProducerRecord[String, Array[Byte]](topic, null, null, "key", "value".getBytes(UTF_8),
      (for {(k, v) <- headers} yield new RecordHeader(k, v.getBytes(UTF_8)): Header).toList.asJava
    )

  def await[T](x: Awaitable[T]): T = Await.result(x, Duration.Inf)
}
