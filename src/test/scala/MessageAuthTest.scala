import java.nio.charset.StandardCharsets
import java.util.Base64

import com.ubirch.messageauth.AuthCheckers
import org.scalatest.{FlatSpec, Matchers}

class MessageAuthTest extends FlatSpec with Matchers {
  // ignored by default, because requires username and password to be passed in through env variables
  "checkCumulocity" should "authorize with basic auth passed in" ignore {
    val username = System.getenv("TEST_USERNAME")
    val password = System.getenv("TEST_PASSWORD")
    val basicAuth = s"Basic ${Base64.getEncoder.encodeToString(s"$username:$password".getBytes(StandardCharsets.UTF_8))}"

    AuthCheckers.checkCumulocity(Map("Authorization" -> basicAuth)) should equal (true)
  }

  // our cumulocity tenant doesn't yet support logging in through OAuth, so this is disabled
  it should "authorize with oauth tokens passed via cookie" ignore {
    val oauthToken = System.getenv("TEST_OAUTH_TOKEN")
    val xsrfToken = System.getenv("TEST_XSRF_TOKEN")
    val headers = Map("X-XSRF-TOKEN" -> xsrfToken, "Cookie" -> s"authorization=$oauthToken")

    AuthCheckers.checkCumulocity(headers) should equal (true)
  }
}
