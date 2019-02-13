package com.ubirch.messageauth

object AuthCheckers {
  def alwaysAccept(_auth: String) = true
  def checkCumulocity(auth: String): Boolean = {
    ???
  }

  def get: PartialFunction[String, AuthChecker] = {
    case "alwaysAccept" => alwaysAccept
    case "checkCumulocity" => checkCumulocity
  }
}
