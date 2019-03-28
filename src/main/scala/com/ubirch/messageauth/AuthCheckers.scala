package com.ubirch.messageauth

import java.nio.charset.StandardCharsets
import java.util.Base64

import com.cumulocity.sdk.client.{PlatformBuilder, SDKException}
import com.typesafe.scalalogging.StrictLogging
import com.ubirch.messageauth.AuthCheckers.AuthChecker
import com.ubirch.niomon.base.NioMicroservice

import scala.util.Try

class AuthCheckers(context: NioMicroservice.Context) extends StrictLogging {
  val defaultCumulocityBaseUrl: String = context.config.getString("cumulocity.baseUrl")
  val defaultCumulocityTenant: String = context.config.getString("cumulocity.tenant")

  def alwaysAccept(_headers: Map[String, String]) = true

  def alwaysReject(_headers: Map[String, String]) = false

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

  implicit object CheckCumulocityOAuthKey extends NioMicroservice.CacheKey[(Map[String, String], CumulocityInfo)] {
    override def key(headersAndInfo: (Map[String, String], CumulocityInfo)): String =
      (headersAndInfo._1("X-XSRF-TOKEN"), headersAndInfo._1("Authorization"), headersAndInfo._1("Cookie"), headersAndInfo._2).toString()
  }

  // we cache authentication iff it is successful!
  lazy val checkCumulocityOAuthCached: (Map[String, String], CumulocityInfo) => Boolean =
    context.cached(checkCumulocityOAuth _).buildCache("cumulocity-oauth-cache", shouldCache = { isAuth => isAuth })

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

  def get: PartialFunction[String, AuthChecker] = {
    case "alwaysAccept" => alwaysAccept
    case "checkCumulocity" => checkCumulocity
  }

  def getDefault: AuthChecker = get(context.config.getString("checkingStrategy"))
}

object AuthCheckers {
  type AuthChecker = Map[String, String] => Boolean
}
