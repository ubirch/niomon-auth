package com.ubirch.messageauth

import java.nio.charset.StandardCharsets
import java.util.{Base64, UUID}

import com.cumulocity.sdk.client.{PlatformBuilder, SDKException}
import com.softwaremill.sttp._
import com.typesafe.scalalogging.StrictLogging
import com.ubirch.defaults.TokenApi
import com.ubirch.messageauth.AuthCheckers.{AuthChecker, CheckResult}
import com.ubirch.niomon.base.NioMicroservice
import com.ubirch.niomon.util.EnrichedMap.toEnrichedMap
import monix.execution.Scheduler.Implicits.global

import scala.concurrent.duration._
import scala.util.Try

/** Collection of different auth checks */
class AuthCheckers(context: NioMicroservice.Context) extends StrictLogging {
  lazy val defaultCumulocityBaseUrl: String = context.config.getString("cumulocity.baseUrl")
  lazy val defaultCumulocityTenant: String = context.config.getString("cumulocity.tenant")

  val alwaysAccept: AuthChecker = _ => AuthCheckers.boolToArbitraryRejectionCheckResult(true)

  val alwaysReject: AuthChecker = _ => AuthCheckers.boolToArbitraryRejectionCheckResult(false)

  def checkCumulocity(headers: Map[String, String]): CheckResult = {
    val cumulocityInfo = getCumulocityInfo(headers)
    headers.CaseInsensitive.get(HeaderKeys.AUTHORIZATION) match {
      case Some(auth) if auth.startsWith("Basic ") => checkCumulocityBasicCached(auth, cumulocityInfo)
      case None => checkCumulocityOAuthCached(headers, cumulocityInfo)
    }
  }

  case class CumulocityInfo(baseUrl: String, tenant: String)

  def getCumulocityInfo(headers: Map[String, String]): CumulocityInfo = {
    CumulocityInfo(
      headers.CaseInsensitive.getOrElse(HeaderKeys.XCUMULOCITYBASEURL, defaultCumulocityBaseUrl),
      headers.CaseInsensitive.getOrElse(HeaderKeys.XCUMULOCITYTENANT, defaultCumulocityTenant))
  }

  // we cache authentication iff it is successful!
  lazy val checkCumulocityBasicCached: (String, CumulocityInfo) => CheckResult =
    context.cached(checkCumulocityBasic _).buildCache(name = "cumulocity-basic-auth-cache", shouldCache = { x => x.isAuthPassed })

  def checkCumulocityBasic(basicAuth: String, cumulocityInfo: CumulocityInfo): CheckResult = {
    logger.debug("doing basic authentication")

    val basicAuthDecoded = new String(Base64.getDecoder.decode(basicAuth.stripPrefix("Basic ")), StandardCharsets.UTF_8)
    val Array(username, password) = basicAuthDecoded.split(":", 2)

    val cumulocity = PlatformBuilder.platform()
      .withBaseUrl(cumulocityInfo.baseUrl)
      .withTenant(cumulocityInfo.tenant)
      .withUsername(username)
      .withPassword(password)
      .build()

    val res = Try(cumulocity.getInventoryApi)

    res.failed.foreach {
      case e: SDKException =>
        if (e.getHttpStatus != 401) {
          logger.error(s"Cumulocity error", e)
        }
      case _ =>
    }

    cumulocity.close()

    CheckResult(rejectionReason = res.failed.toOption)
  }

  // we cache authentication if it is successful!
  lazy val checkCumulocityOAuthCached: (Map[String, String], CumulocityInfo) => CheckResult =
    context.cached(checkCumulocityOAuth _)
      .buildCache("cumulocity-oauth-cache", shouldCache = { x => x.isAuthPassed })(
        hi => (
          hi._1.get(HeaderKeys.XXSRFTOKEN),
          hi._1.get(HeaderKeys.AUTHORIZATION),
          hi._1.get(HeaderKeys.COOKIE),
          hi._2
          ).toString()
      )

  private val authorizationCookieRegex = "authorization=([^;]*)".r.unanchored

  def checkCumulocityOAuth(headers: Map[String, String], cumulocityInfo: CumulocityInfo): CheckResult = {
    logger.debug("doing OAuth authentication")
    logger.warn("OAuth authentication is unsupported at `ubirch` tenant")

    val xsrfToken = headers.CaseInsensitive.get(HeaderKeys.XXSRFTOKEN)
    val authorizationHeader = headers.CaseInsensitive.get(HeaderKeys.AUTHORIZATION)
    val authorizationCookie = headers.CaseInsensitive.get(HeaderKeys.COOKIE).flatMap { cookiesStr =>
      cookiesStr match {
        case authorizationCookieRegex(authCookie) => Some(authCookie)
        case _ => None
      }
    }

    val oAuthToken = authorizationHeader.orElse(authorizationCookie)

    val cumulocity = PlatformBuilder.platform()
      .withBaseUrl(cumulocityInfo.baseUrl)
      .withTenant(cumulocityInfo.tenant)
      .withOAuthAccessToken(oAuthToken.orNull)
      .withXsrfToken(xsrfToken.orNull)
      .build()

    val res = Try(cumulocity.getInventoryApi)

    cumulocity.close()

    CheckResult(rejectionReason = res.failed.toOption)
  }

  def checkMulti(headers: Map[String, String]): CheckResult = {
    headers.CaseInsensitive.getOrElse(HeaderKeys.XUBIRCHAUTHTYPE, "cumulocity") match {
      case "cumulocity" =>
        logger.debug("checkMulti: cumulocity")
        checkCumulocity(headers)
      case "keycloak" | "ubirch" =>
        logger.debug("checkMulti: keycloak/ubirch")
        checkUbirchCached(headers)
      case "ubirch-token" =>
        logger.debug("checkMulti: ubirch-token")
        checkUbirchTokenCached(headers)
    }
  }

  implicit val sttpBackend: EitherBackend[Nothing] = new EitherBackend[Nothing](HttpURLConnectionBackend(
    options = SttpBackendOptions.connectionTimeout(10.seconds)
  ))

  lazy val checkUbirchCached: AuthChecker =
    context.cached(checkUbirch _).buildCache("ubirch-auth-cache", shouldCache = { cr => cr.isAuthPassed })(
      h => (h.get(HeaderKeys.XUBIRCHHARDWAREID), h.get(HeaderKeys.XUBIRCHCREDENTIAL)).toString()
    )

  def checkUbirch(headers: Map[String, String]): CheckResult = (for {
    _ <- Right(()) // for some reason for expressions have to start with a `<-` binding

    currentHeader = headers.seq.keys.toList.mkString(", ")
    _ = logger.debug(s"checkUbirch: received headers = $currentHeader")

    rawUrl <- Try(context.config.getString("ubirch.authUrl")).toEither
    uri <- Uri.parse(rawUrl).toEither
      .left.map(cause => new IllegalArgumentException(s"could not parse ubirch.authUrl = [$rawUrl]", cause))

    hardwareId <- headers.CaseInsensitive.get(HeaderKeys.XUBIRCHHARDWAREID)
      .toRight(new NoSuchElementException("missing X-Ubirch-Hardware-Id header"))

    ubirchCredential <- headers.CaseInsensitive.get(HeaderKeys.XUBIRCHCREDENTIAL)
      .toRight(new NoSuchElementException("missing X-Ubirch-Credential header"))

    deviceInfoTokenResponse <- sttp.get(uri)
      .header(HeaderKeys.XUBIRCHHARDWAREID, hardwareId)
      .header(HeaderKeys.XUBIRCHCREDENTIAL, ubirchCredential)
      .readTimeout(10.seconds)
      .send()
      .left.map(new RuntimeException(s"request to $rawUrl was not successful", _))

    deviceInfoToken <- deviceInfoTokenResponse.body.left.map(errBody => new IllegalArgumentException(
      s"response from $rawUrl was not successful; status code = ${deviceInfoTokenResponse.code}; body = [$errBody]"
    ))

    successfulResult = CheckResult(rejectionReason = None, headersToAdd = Map(HeaderKeys.XUBIRCHDEVICEINFOTOKEN -> deviceInfoToken))
  } yield successfulResult).fold({ error =>
    logger.error("error while authenticating", error)
    CheckResult(rejectionReason = Some(error))
  }, identity)

  lazy val checkUbirchTokenCached: AuthChecker =
    context.cached(checkUbirchToken _).buildCache("ubirch-auth-cache", shouldCache = { cr => cr.isAuthPassed })(
      h => (h.get(HeaderKeys.XUBIRCHHARDWAREID), h.get(HeaderKeys.XUBIRCHCREDENTIAL)).toString()
    )

  def checkUbirchToken(headers: Map[String, String]): CheckResult = (for {
    _ <- Right(()) // for some reason for expressions have to start with a `<-` binding

    currentHeader = headers.seq.keys.toList.mkString(", ")
    _ = logger.debug(s"checkUbirchToken: received headers = $currentHeader")

    hardwareId <- headers.CaseInsensitive.get(HeaderKeys.XUBIRCHHARDWAREID)
      .toRight(new NoSuchElementException("missing X-Ubirch-Hardware-Id header"))

    ubirchToken <- headers.CaseInsensitive.get(HeaderKeys.XUBIRCHCREDENTIAL)
      .filter(_.nonEmpty)
      .toRight(new NoSuchElementException("missing X-Ubirch-Credential header"))

    isValid <- TokenApi
      //We use sync here because it is the easier way to integrate with current processing code.
      .externalStateVerifySync(ubirchToken, UUID.fromString(hardwareId))(10.seconds)
      .left.map(new RuntimeException("request to token service was not successful", _))

    _ <- if(isValid) Right(isValid) else Left(new RuntimeException("Token is invalid"))

    successfulResult = CheckResult(rejectionReason = None, headersToAdd = Map(HeaderKeys.XUBIRCHDEVICEINFOTOKEN -> ubirchToken))
  } yield successfulResult).fold({ error =>
    logger.error("error while authenticating", error)
    CheckResult(rejectionReason = Some(error))
  }, identity)

  def get: PartialFunction[String, AuthChecker] = {
    case "alwaysAccept" => alwaysAccept
    case "checkCumulocity" => checkCumulocity
    case "checkMulti" => checkMulti
  }

  def getDefault: AuthChecker = get(context.config.getString("checkingStrategy"))
}

object AuthCheckers {
  case class CheckResult(rejectionReason: Option[Throwable], headersToAdd: Map[String, String] = Map()) {
    def isAuthPassed: Boolean = rejectionReason.isEmpty
  }

  def boolToArbitraryRejectionCheckResult(isAuthPassed: Boolean): CheckResult =
    CheckResult(rejectionReason = if (isAuthPassed) None else Some(new Exception("arbitrary rejection")))

  type AuthChecker = Map[String, String] => CheckResult

}
