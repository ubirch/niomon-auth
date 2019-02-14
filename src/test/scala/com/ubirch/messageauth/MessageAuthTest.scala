package com.ubirch.messageauth

import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64

import akka.NotUsed
import akka.kafka.ConsumerMessage
import akka.stream.scaladsl.{Flow, Keep, Sink, Source}
import com.ubirch.kafka._
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.kafka.common.header.Header
import org.apache.kafka.common.header.internals.{RecordHeader, RecordHeaders}
import org.scalatest.{FlatSpec, Matchers}

import scala.collection.JavaConverters._
import scala.concurrent.Await
import scala.concurrent.duration._

class MessageAuthTest extends FlatSpec with Matchers {
  // ignored by default, because requires username and password to be passed in through env variables
  "checkCumulocity" should "authorize with basic auth passed in" ignore {
    val username = System.getenv("TEST_USERNAME")
    val password = System.getenv("TEST_PASSWORD")
    val basicAuth = s"Basic ${Base64.getEncoder.encodeToString(s"$username:$password".getBytes(UTF_8))}"

    AuthCheckers.checkCumulocity(Map("Authorization" -> basicAuth)) should equal(true)
  }

  // our cumulocity tenant doesn't yet support logging in through OAuth, so this is disabled
  it should "authorize with oauth tokens passed via cookie" ignore {
    val oauthToken = System.getenv("TEST_OAUTH_TOKEN")
    val xsrfToken = System.getenv("TEST_XSRF_TOKEN")
    val headers = Map("X-XSRF-TOKEN" -> xsrfToken, "Cookie" -> s"authorization=$oauthToken")

    AuthCheckers.checkCumulocity(headers) should equal(true)
  }

  "authFlow" should "direct messages to authorized topic if authorized" in {
    val flow = authFlow(AuthCheckers.alwaysAccept)

    val res = run(flow)(
      arbitraryMessageWithHeaders("X-Please-Let-Me-Pass" -> "true"),
      arbitraryMessageWithHeaders("X-Foo" -> "foo"),
      arbitraryMessageWithHeaders("X-Bar" -> "bar"),
    )

    res(authorizedTopic).size should equal(3)
    res.get(unauthorizedTopic) should equal(None)
  }

  it should "direct messages to unauthorized topic if unauthorized" in {
    val flow = authFlow(AuthCheckers.alwaysReject)

    val res = run(flow)(
      arbitraryMessageWithHeaders("X-Please-Let-Me-Pass" -> "true"),
      arbitraryMessageWithHeaders("X-Foo" -> "foo"),
      arbitraryMessageWithHeaders("X-Bar" -> "bar")
    )

    res.get(authorizedTopic) should equal(None)
    res(unauthorizedTopic).size should equal(3)
  }

  it should "direct messages according to passed AuthChecker" in {
    val flow = authFlow { headers => headers.get("X-Must-Be-Even").exists(_.toInt % 2 == 0) }

    val res = run(flow)(
      arbitraryMessageWithHeaders("X-Must-Be-Even" -> "0"),
      arbitraryMessageWithHeaders("X-Must-Be-Even" -> "1"),
      arbitraryMessageWithHeaders("X-Must-Be-Even" -> "2")
    )

    res(authorizedTopic).map(_.record.headersScala("X-Must-Be-Even")) should contain only ("0", "2")
    res(unauthorizedTopic).map(_.record.headersScala("X-Must-Be-Even")) should contain only "1"
  }

  private def run(flow: Flow[FlowIn, FlowOut, NotUsed])(messages: FlowIn*) =
    Await.result(Source(messages.toList)
      .via(flow)
      .groupBy(2, x => x.record.topic())
      .map(List(_))
      .reduce((acc, n) => n ++ acc)
      .mergeSubstreams
      .toMat(Sink.seq)(Keep.right)
      .run(), 5.seconds)
      .groupBy(_.head.record.topic()).mapValues(_.flatten)

  private def arbitraryMessageWithHeaders(headers: (String, String)*): ConsumerMessage.CommittableMessage[String, Array[Byte]] =
    ConsumerMessage.CommittableMessage(
      new ConsumerRecord[String, Array[Byte]]("foo", 0, 0, 0, null, 0, 3, 5, "key", "value".getBytes(UTF_8),
        new RecordHeaders((for {(k, v) <- headers} yield new RecordHeader(k, v.getBytes(UTF_8)): Header).toList.asJava)),
      null)
}
