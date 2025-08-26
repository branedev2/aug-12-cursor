import scala.io.Source
import java.io.{PrintWriter, File}
import scala.util.{Try, Success, Failure}
import play.api.mvc._
import play.api.http._
import play.api.libs.json._
import play.api.routing._
import scala.collection.mutable.StringBuilder
import java.util.logging.{Logger, Level}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(request: Request[AnyContent]): String = {
  val userInput = request.getQueryString("input").getOrElse("")
  val message = "Welcome to our site"
  
  // ruleid: scala-format-string-manipulation
  printf(userInput, message)
  
  "Response sent"
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_2(request: Request[AnyContent]): String = {
  val userInput = request.getQueryString("format").getOrElse("%s")
  val username = "admin"
  val sb = new StringBuilder()
  
  // ruleid: scala-format-string-manipulation
  sb.append(String.format(userInput, username))
  
  sb.toString()
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_3(request: Request[AnyContent]): Unit = {
  val logger = Logger.getLogger("SecurityLogger")
  val formatString = request.getQueryString("logFormat").getOrElse("%s: %s")
  val logLevel = "INFO"
  val logMessage = "User logged in"
  
  // ruleid: scala-format-string-manipulation
  logger.info(String.format(formatString, logLevel, logMessage))
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_4(request: Request[AnyContent]): String = {
  val formatPattern = request.body.asFormUrlEncoded.flatMap(_.get("pattern").flatMap(_.headOption)).getOrElse("%d items found")
  val itemCount = 42
  
  // ruleid: scala-format-string-manipulation
  String.format(formatPattern, Integer.valueOf(itemCount))
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_5(request: Request[AnyContent]): Unit = {
  val userFormat = request.headers.get("X-Format-String").getOrElse("%s")
  val data = "sensitive data"
  val writer = new PrintWriter(new File("output.txt"))
  
  // ruleid: scala-format-string-manipulation
  writer.printf(userFormat, data)
  writer.close()
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_6(request: Request[AnyContent]): String = {
  val formatStr = request.cookies.get("formatPreference").map(_.value).getOrElse("%s - %s")
  val username = "john"
  val role = "admin"
  
  // ruleid: scala-format-string-manipulation
  String.format(formatStr, username, role)
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_7(request: Request[AnyContent]): Unit = {
  val console = System.console()
  val formatPattern = request.body.asJson.flatMap(json => (json \ "format").asOpt[String]).getOrElse("%s")
  val message = "System message"
  
  // ruleid: scala-format-string-manipulation
  console.printf(formatPattern, message)
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_8(request: Request[AnyContent]): String = {
  val userInput = request.getQueryString("template").getOrElse("%s")
  val data = Array("sensitive", "information", "here")
  val sb = new StringBuilder()
  
  for (item <- data) {
    // ruleid: scala-format-string-manipulation
    sb.append(String.format(userInput, item))
    sb.append("\n")
  }
  
  sb.toString()
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_9(request: Request[AnyContent]): Unit = {
  val logger = Logger.getLogger("AppLogger")
  val formatStr = request.getQueryString("logStyle").getOrElse("%s")
  val error = new Exception("Something went wrong")
  
  // ruleid: scala-format-string-manipulation
  logger.severe(String.format(formatStr, error.getMessage))
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_10(request: Request[AnyContent]): String = {
  val formatString = request.body.asFormUrlEncoded
    .flatMap(_.get("format"))
    .flatMap(_.headOption)
    .getOrElse("%s: %s")
  
  val key = "username"
  val value = "admin"
  
  // ruleid: scala-format-string-manipulation
  String.format(formatString, key, value)
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_11(request: Request[AnyContent]): Unit = {
  val formatStr = request.headers.get("Content-Type") match {
    case Some("application/json") => request.body.asJson.flatMap(json => (json \ "format").asOpt[String]).getOrElse("%s")
    case _ => request.getQueryString("format").getOrElse("%s")
  }
  
  val message = "Processing complete"
  
  // ruleid: scala-format-string-manipulation
  System.out.printf(formatStr, message)
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_12(request: Request[AnyContent]): String = {
  val formatPattern = Try {
    request.body.asJson.flatMap(json => (json \ "pattern").asOpt[String]).getOrElse("%s")
  }.getOrElse("%s")
  
  val data = "confidential"
  
  // ruleid: scala-format-string-manipulation
  String.format(formatPattern, data)
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_13(request: Request[AnyContent]): Unit = {
  val sb = new StringBuilder()
  val formatStr = request.getQueryString("display").getOrElse("%s - %s")
  val firstName = "John"
  val lastName = "Doe"
  
  // ruleid: scala-format-string-manipulation
  sb.append(String.format(formatStr, firstName, lastName))
  println(sb.toString())
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_14(request: Request[AnyContent]): String = {
  val formatString = request.cookies.get("displayFormat")
    .map(_.value)
    .getOrElse("%s: %d")
  
  val product = "Laptop"
  val price = 999
  
  // ruleid: scala-format-string-manipulation
  String.format(formatString, product, Integer.valueOf(price))
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=1}

def bad_case_15(request: Request[AnyContent]): Unit = {
  val logger = Logger.getLogger("TransactionLogger")
  val formatPattern = request.headers.get("X-Log-Format").getOrElse("%s")
  val transactionId = "TX123456"
  
  // ruleid: scala-format-string-manipulation
  logger.info(String.format(formatPattern, transactionId))
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

// True Negative Examples (Safe Code)

def good_case_1(request: Request[AnyContent]): String = {
  val userInput = request.getQueryString("input").getOrElse("")
  val message = "Welcome to our site"
  
  // ok: scala-format-string-manipulation
  printf("%s", userInput)
  
  "Response sent"
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_2(request: Request[AnyContent]): String = {
  val userInput = request.getQueryString("format").getOrElse("%s")
  val username = "admin"
  val sb = new StringBuilder()
  
  // ok: scala-format-string-manipulation
  sb.append(String.format("%s", username))
  
  sb.toString()
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_3(request: Request[AnyContent]): Unit = {
  val logger = Logger.getLogger("SecurityLogger")
  val formatString = "%s: %s" // Static format string
  val logLevel = request.getQueryString("logLevel").getOrElse("INFO")
  val logMessage = request.getQueryString("message").getOrElse("User logged in")
  
  // ok: scala-format-string-manipulation
  logger.info(String.format(formatString, logLevel, logMessage))
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_4(request: Request[AnyContent]): String = {
  val itemCount = Try(request.getQueryString("count").getOrElse("0").toInt).getOrElse(0)
  
  // ok: scala-format-string-manipulation
  String.format("%d items found", Integer.valueOf(itemCount))
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_5(request: Request[AnyContent]): Unit = {
  val data = request.getQueryString("data").getOrElse("default data")
  val writer = new PrintWriter(new File("output.txt"))
  
  // ok: scala-format-string-manipulation
  writer.printf("%s", data)
  writer.close()
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_6(request: Request[AnyContent]): String = {
  val username = request.getQueryString("username").getOrElse("guest")
  val role = request.getQueryString("role").getOrElse("user")
  
  // ok: scala-format-string-manipulation
  String.format("%s - %s", username, role)
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_7(request: Request[AnyContent]): Unit = {
  val console = System.console()
  val message = request.body.asJson.flatMap(json => (json \ "message").asOpt[String]).getOrElse("No message")
  
  // ok: scala-format-string-manipulation
  console.printf("%s", message)
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_8(request: Request[AnyContent]): String = {
  val userInput = request.getQueryString("data").getOrElse("")
  val data = Array("item1", "item2", "item3")
  val sb = new StringBuilder()
  
  for (item <- data) {
    // ok: scala-format-string-manipulation
    sb.append(String.format("%s: %s", item, userInput))
    sb.append("\n")
  }
  
  sb.toString()
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_9(request: Request[AnyContent]): Unit = {
  val logger = Logger.getLogger("AppLogger")
  val errorMessage = request.getQueryString("error").getOrElse("Unknown error")
  
  // ok: scala-format-string-manipulation
  logger.severe(String.format("Error occurred: %s", errorMessage))
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_10(request: Request[AnyContent]): String = {
  val key = request.body.asFormUrlEncoded
    .flatMap(_.get("key"))
    .flatMap(_.headOption)
    .getOrElse("default")
  
  val value = request.body.asFormUrlEncoded
    .flatMap(_.get("value"))
    .flatMap(_.headOption)
    .getOrElse("default")
  
  // ok: scala-format-string-manipulation
  String.format("%s: %s", key, value)
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_11(request: Request[AnyContent]): Unit = {
  val message = request.headers.get("X-Message").getOrElse("No message")
  
  // ok: scala-format-string-manipulation
  System.out.printf("Message received: %s", message)
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_12(request: Request[AnyContent]): String = {
  val data = Try {
    request.body.asJson.flatMap(json => (json \ "data").asOpt[String]).getOrElse("default")
  }.getOrElse("error")
  
  // ok: scala-format-string-manipulation
  String.format("Data: %s", data)
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_13(request: Request[AnyContent]): Unit = {
  val sb = new StringBuilder()
  val firstName = request.getQueryString("firstName").getOrElse("John")
  val lastName = request.getQueryString("lastName").getOrElse("Doe")
  
  // ok: scala-format-string-manipulation
  sb.append(String.format("Name: %s %s", firstName, lastName))
  println(sb.toString())
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_14(request: Request[AnyContent]): String = {
  val product = request.cookies.get("product")
    .map(_.value)
    .getOrElse("Unknown")
  
  val price = Try(request.getQueryString("price").getOrElse("0").toInt).getOrElse(0)
  
  // ok: scala-format-string-manipulation
  String.format("Product: %s, Price: %d", product, Integer.valueOf(price))
}
// {/fact}
// {fact rule=untrusted-format-strings@v1.0 defects=0}

def good_case_15(request: Request[AnyContent]): Unit = {
  val logger = Logger.getLogger("TransactionLogger")
  val transactionId = request.headers.get("X-Transaction-ID").getOrElse("Unknown")
  
  // ok: scala-format-string-manipulation
  logger.info(String.format("Transaction ID: %s", transactionId))
}
// {/fact}