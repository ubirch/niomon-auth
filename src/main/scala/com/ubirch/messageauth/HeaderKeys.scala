package com.ubirch.messageauth

object HeaderKeys {
  val XUBIRCHCREDENTIAL: String = "X-Ubirch-Credential".toLowerCase;
  val XUBIRCHHARDWAREID: String = "X-Ubirch-Hardware-Id".toLowerCase;
  val XUBIRCHAUTHTYPE: String = "X-Ubirch-Auth-Type".toLowerCase;
  val XUBIRCHDEVICEINFOTOKEN: String = "X-Ubirch-DeviceInfo-Token".toLowerCase;
  val AUTHORIZATION: String = "Authorization".toLowerCase;
  val XXSRFTOKEN: String = "X-XSRF-TOKEN".toLowerCase;
  val XCUMULOCITYBASEURL: String = "X-Cumulocity-BaseUrl".toLowerCase;
  val XCUMULOCITYTENANT: String = "X-Cumulocity-Tenant".toLowerCase;
  val XNIOMONPURGECACHES: String = "X-Niomon-Purge-Caches".toLowerCase;
  val CONTENTTYPE: String = "Content-Type".toLowerCase;
  val COOKIE: String = "Cookie".toLowerCase;
}
