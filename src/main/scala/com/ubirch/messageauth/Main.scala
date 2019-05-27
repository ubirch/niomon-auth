package com.ubirch.messageauth

import com.ubirch.niomon.base.NioMicroserviceLive

object Main {
  def main(args: Array[String]): Unit = {
    val _ = NioMicroserviceLive("message-auth", MessageAuthMicroservice(new AuthCheckers(_).getDefault)).runUntilDoneAndShutdownProcess
  }
}
