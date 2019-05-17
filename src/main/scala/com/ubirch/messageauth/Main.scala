package com.ubirch.messageauth

object Main {
  def main(args: Array[String]): Unit = {
    val _ = new MessageAuthMicroservice(new AuthCheckers(_).getDefault).runUntilDoneAndShutdownProcess
  }
}
