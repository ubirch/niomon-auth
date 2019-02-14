package com.ubirch.messageauth

import java.nio.charset.StandardCharsets
import java.util.Base64

import com.cumulocity.sdk.client.PlatformBuilder
import com.typesafe.scalalogging.StrictLogging

import scala.util.Try

object AuthCheckers extends StrictLogging {
  val defaultCumulocityBaseUrl: String = conf.getString("cumulocity.baseUrl")
  val defaultCumulocityTenant: String = conf.getString("cumulocity.tenant")

  def alwaysAccept(_headers: Map[String, String]) = true

  def checkCumulocity(headers: Map[String, String]): Boolean = {
    headers.get("Authorization") match {
      case Some(auth) if auth.startsWith("Basic ") => checkCumulocityBasic(auth)
      case None => checkCumulocityOAuth(headers)
    }
  }

  def checkCumulocityBasic(basicAuth: String): Boolean = {
    logger.debug("doing basic authentication")

    val basicAuthDecoded = new String(Base64.getDecoder.decode(basicAuth.stripPrefix("Basic ")), StandardCharsets.UTF_8)
    val Array(username, password) = basicAuthDecoded.split(":", 2)

    val cumulocity = PlatformBuilder.platform()
      .withBaseUrl(defaultCumulocityBaseUrl)
      .withTenant(defaultCumulocityTenant)
      .withUsername(username)
      .withPassword(password)
      .build()

    val res = Try(cumulocity.getInventoryApi).isSuccess // cumulocity api throws exception if unauthorized

    cumulocity.close()

    res
  }

  private val authorizationCookieRegex = "authorization=([^;]*)".r.unanchored

  def checkCumulocityOAuth(headers: Map[String, String]): Boolean = {
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
      .withBaseUrl(defaultCumulocityBaseUrl) // TODO: support different baseUrls for different messages
      .withTenant(defaultCumulocityTenant) // TODO: support different tenants for different messages
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
}
