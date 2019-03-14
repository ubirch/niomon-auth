package com.ubirch.messageauth

object Main {
  def main(args: Array[String]): Unit = {
    new MessageAuthMicroservice(new AuthCheckers(_).getDefault).runUntilDone
  }
}
