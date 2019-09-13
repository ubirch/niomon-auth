package com.ubirch.messageauth

import java.nio.charset.StandardCharsets
import java.util.Base64

import com.cumulocity.sdk.client.{PlatformBuilder, SDKException}
import com.softwaremill.sttp._
import com.typesafe.scalalogging.StrictLogging
import com.ubirch.messageauth.AuthCheckers.AuthChecker
import com.ubirch.niomon.base.NioMicroservice

import scala.util.Try

class AuthCheckers(context: NioMicroservice.Context) extends StrictLogging {
  lazy val defaultCumulocityBaseUrl: String = context.config.getString("cumulocity.baseUrl")
  lazy val defaultCumulocityTenant: String = context.config.getString("cumulocity.tenant")

  val alwaysAccept: Map[String, String] => Boolean = _ => true

  val alwaysReject: Map[String, String] => Boolean = _ => false

  def checkCumulocity(headers: Map[String, String]): Boolean = {
    val cumulocityInfo = getCumulocityInfo(headers)
    headers.get("Authorization") match {
      case Some(auth) if auth.startsWith("Basic ") => checkCumulocityBasicCached(auth, cumulocityInfo)
      case None => checkCumulocityOAuthCached(headers, cumulocityInfo)
    }
  }

  case class CumulocityInfo(baseUrl: String, tenant: String)

  def getCumulocityInfo(headers: Map[String, String]): CumulocityInfo = {
    CumulocityInfo(headers.getOrElse("X-Cumulocity-BaseUrl", defaultCumulocityBaseUrl),
      headers.getOrElse("X-Cumulocity-Tenant", defaultCumulocityTenant))
  }

  // we cache authentication iff it is successful!
  lazy val checkCumulocityBasicCached: (String, CumulocityInfo) => Boolean =
    context.cached(checkCumulocityBasic _).buildCache(name = "cumulocity-basic-auth-cache", shouldCache = { isAuth => isAuth })

  def checkCumulocityBasic(basicAuth: String, cumulocityInfo: CumulocityInfo): Boolean = {
    logger.debug("doing basic authentication")

    val basicAuthDecoded = new String(Base64.getDecoder.decode(basicAuth.stripPrefix("Basic ")), StandardCharsets.UTF_8)
    val Array(username, password) = basicAuthDecoded.split(":", 2)

    val cumulocity = PlatformBuilder.platform()
      .withBaseUrl(cumulocityInfo.baseUrl)
      .withTenant(cumulocityInfo.tenant)
      .withUsername(username)
      .withPassword(password)
      .build()

    val rawRes = Try(cumulocity.getInventoryApi)

    rawRes.failed.foreach {
      case e: SDKException =>
        if (e.getHttpStatus != 401) {
          logger.error(s"Cumulocity error", e)
        }
      case _ =>
    }

    val res = rawRes.isSuccess // cumulocity api throws exception if unauthorized

    cumulocity.close()

    res
  }

  // we cache authentication iff it is successful!
  lazy val checkCumulocityOAuthCached: (Map[String, String], CumulocityInfo) => Boolean =
    context.cached(checkCumulocityOAuth _).buildCache("cumulocity-oauth-cache", shouldCache = { isAuth => isAuth })(
      hi => (hi._1.get("X-XSRF-TOKEN"), hi._1.get("Authorization"), hi._1.get("Cookie"), hi._2).toString()
    )

  private val authorizationCookieRegex = "authorization=([^;]*)".r.unanchored

  def checkCumulocityOAuth(headers: Map[String, String], cumulocityInfo: CumulocityInfo): Boolean = {
    logger.debug("doing OAuth authentication")
    logger.warn("OAuth authentication is unsupported at `ubirch` tenant")

    val xsrfToken = headers.get("X-XSRF-TOKEN")
    val authorizationHeader = headers.get("Authorization")
    val authorizationCookie = headers.get("Cookie").flatMap { cookiesStr =>
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

    val res = Try(cumulocity.getInventoryApi).isSuccess // cumulocity api throws exception if unauthorized

    cumulocity.close()

    res
  }

  def checkMulti(headers: Map[String, String]): Boolean = {
    headers.getOrElse("X-Ubirch-Auth-Type", "cumulocity") match {
      case "cumulocity" => checkCumulocity(headers)
      case "keycloak" | "ubirch" => checkUbirchCached(headers)
    }
  }

  implicit val sttpBackend: SttpBackend[Id, Nothing] = HttpURLConnectionBackend()

  lazy val checkUbirchCached: AuthChecker =
    context.cached(checkUbirch _).buildCache("ubirch-auth-cache", shouldCache = { isAuth => isAuth })(
      h => (h.get("X-Ubirch-Hardware-Id"), h.get("X-Ubirch-Credential")).toString()
    )

  def checkUbirch(headers: Map[String, String]): Boolean = Try {
    // we receive password in base64, but the keycloak facade expects plain text
    val decodedPassword = new String(Base64.getDecoder.decode(headers("X-Ubirch-Credential")), StandardCharsets.UTF_8)

    val response = sttp.get(Uri.parse(context.config.getString("ubirch.authUrl")).get)
      .header("X-Ubirch-Hardware-Id", headers("X-Ubirch-Hardware-Id"))
      .header("X-Ubirch-Credential", decodedPassword)
      .send()

    response.isSuccess
  }.fold({ error =>
    logger.error("error while authenticating", error)
    false
  }, identity)

  def get: PartialFunction[String, AuthChecker] = {
    case "alwaysAccept" => alwaysAccept
    case "checkCumulocity" => checkCumulocity
    case "checkMulti" => checkMulti
  }

  def getDefault: AuthChecker = get(context.config.getString("checkingStrategy"))
}

object AuthCheckers {
  type AuthChecker = Map[String, String] => Boolean
}
