import org.apache.commons.lang3.StringEscapeUtils
import play.api.mvc._
import play.api.Logger
import play.api.http.HttpVerbs
import play.api.libs.json._
import scala.io.Source
import java.net.URL
import java.net.HttpURLConnection
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.HttpRequest
import akka.http.scaladsl.model.headers.RawHeader
import org.slf4j.LoggerFactory
import scala.util.Try
import scala.util.Success
import scala.util.Failure
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import java.io.BufferedReader
import java.io.InputStreamReader
import javax.servlet.http.HttpServletRequest
import org.springframework.web.bind.annotation._
// {fact rule=file-injection@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(request: Request[AnyContent]): Unit = {
  val logger = Logger("application")
  val userInput = request.getQueryString("username").getOrElse("")
  
  // ruleid: scala-crlf-injection-logs
  logger.info(s"User login attempt: $userInput")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_2(request: Request[AnyContent]): Unit = {
  val logger = Logger("security")
  val ipAddress = request.headers.get("X-Forwarded-For").getOrElse("unknown")
  
  // ruleid: scala-crlf-injection-logs
  logger.warn(s"Suspicious activity detected from IP: $ipAddress")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_3(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(this.getClass)
  val jsonBody = request.body.asJson.getOrElse(Json.obj())
  val userId = (jsonBody \ "userId").asOpt[String].getOrElse("")
  
  // ruleid: scala-crlf-injection-logs
  logger.error(s"Failed authentication for user: $userId")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_4(request: HttpServletRequest): Unit = {
  val logger = LoggerFactory.getLogger("AccessLog")
  val userAgent = request.getHeader("User-Agent")
  
  // ruleid: scala-crlf-injection-logs
  logger.info(s"Request from user agent: $userAgent")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_5(): Unit = {
  val logger = Logger("api")
  val connection = new URL("https://api.example.com/data").openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  
  // ruleid: scala-crlf-injection-logs
  logger.info(s"API response: $response")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_6(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger("TransactionLogger")
  val transactionId = request.body.asFormUrlEncoded.flatMap(_.get("transaction_id").map(_.head)).getOrElse("")
  
  // ruleid: scala-crlf-injection-logs
  logger.info(s"Processing transaction: $transactionId")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_7(request: HttpRequest): Unit = {
  val logger = LoggerFactory.getLogger("SecurityAudit")
  val authToken = request.headers.find(_.name() == "Authorization").map(_.value()).getOrElse("")
  
  // ruleid: scala-crlf-injection-logs
  logger.debug(s"Auth token received: $authToken")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_8(): Unit = {
  val logger = Logger("FileProcessor")
  val fileContent = Source.fromFile(System.getProperty("user.input")).getLines().mkString("\n")
  
  // ruleid: scala-crlf-injection-logs
  logger.info(s"Processing file content: $fileContent")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_9(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(this.getClass)
  val searchQuery = request.getQueryString("q").getOrElse("")
  
  // ruleid: scala-crlf-injection-logs
  logger.info(s"Search query: $searchQuery")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_10(): Unit = {
  val logger = Logger("WebhookHandler")
  val process = Runtime.getRuntime.exec("curl https://api.external.com/webhook")
  val reader = new BufferedReader(new InputStreamReader(process.getInputStream))
  val webhookData = Iterator.continually(reader.readLine()).takeWhile(_ != null).mkString("\n")
  
  // ruleid: scala-crlf-injection-logs
  logger.info(s"Webhook data received: $webhookData")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_11(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger("PaymentProcessor")
  val paymentDetails = request.body.asJson.map(json => (json \ "cardNumber").as[String]).getOrElse("")
  
  // ruleid: scala-crlf-injection-logs
  logger.info(s"Last 4 digits of card: ${paymentDetails.takeRight(4)}")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_12(request: HttpServletRequest): Unit = {
  val logger = Logger("SessionManager")
  val sessionId = request.getSession.getId
  val referrer = request.getHeader("Referer")
  
  // ruleid: scala-crlf-injection-logs
  logger.info(s"Session $sessionId created from referrer: $referrer")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_13(): Unit = {
  val logger = LoggerFactory.getLogger("ConfigLoader")
  val configSource = Source.fromURL(new URL("https://config.example.org/app-config.json")).mkString
  
  // ruleid: scala-crlf-injection-logs
  logger.info(s"Loaded configuration: $configSource")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_14(request: Request[AnyContent]): Unit = {
  val logger = Logger("UserRegistration")
  val email = request.body.asFormUrlEncoded.flatMap(_.get("email").map(_.head)).getOrElse("")
  val name = request.body.asFormUrlEncoded.flatMap(_.get("name").map(_.head)).getOrElse("")
  
  // ruleid: scala-crlf-injection-logs
  logger.info(s"New user registration: $name ($email)")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=1}

def bad_case_15(request: HttpRequest): Unit = {
  val logger = LoggerFactory.getLogger("ErrorTracker")
  val errorMessage = request.entity.toString
  val clientIp = request.headers.find(_.name() == "X-Real-IP").map(_.value()).getOrElse("unknown")
  
  // ruleid: scala-crlf-injection-logs
  logger.error(s"Client error from $clientIp: $errorMessage")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

// True Negatives (Safe Code)

def good_case_1(request: Request[AnyContent]): Unit = {
  val logger = Logger("application")
  val userInput = request.getQueryString("username").getOrElse("")
  
  // ok: scala-crlf-injection-logs
  logger.info(s"User login attempt: ${StringEscapeUtils.escapeJava(userInput)}")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_2(request: Request[AnyContent]): Unit = {
  val logger = Logger("security")
  val ipAddress = request.headers.get("X-Forwarded-For").getOrElse("unknown")
  
  // ok: scala-crlf-injection-logs
  logger.warn(s"Suspicious activity detected from IP: ${StringEscapeUtils.escapeJava(ipAddress)}")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_3(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(this.getClass)
  val jsonBody = request.body.asJson.getOrElse(Json.obj())
  val userId = (jsonBody \ "userId").asOpt[String].getOrElse("")
  
  // ok: scala-crlf-injection-logs
  logger.error(s"Failed authentication for user: ${StringEscapeUtils.escapeJava(userId)}")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_4(request: HttpServletRequest): Unit = {
  val logger = LoggerFactory.getLogger("AccessLog")
  val userAgent = request.getHeader("User-Agent")
  
  // ok: scala-crlf-injection-logs
  logger.info(s"Request from user agent: ${StringEscapeUtils.escapeJava(userAgent)}")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_5(): Unit = {
  val logger = Logger("api")
  val connection = new URL("https://api.example.com/data").openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  
  // ok: scala-crlf-injection-logs
  logger.info(s"API response: ${StringEscapeUtils.escapeJava(response)}")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_6(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger("TransactionLogger")
  val transactionId = request.body.asFormUrlEncoded.flatMap(_.get("transaction_id").map(_.head)).getOrElse("")
  
  // Using a sanitization helper function
  def sanitize(input: String): String = StringEscapeUtils.escapeJava(input)
  
  // ok: scala-crlf-injection-logs
  logger.info(s"Processing transaction: ${sanitize(transactionId)}")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_7(request: HttpRequest): Unit = {
  val logger = LoggerFactory.getLogger("SecurityAudit")
  val authToken = request.headers.find(_.name() == "Authorization").map(_.value()).getOrElse("")
  
  // ok: scala-crlf-injection-logs
  val sanitizedToken = StringEscapeUtils.escapeJava(authToken)
  logger.debug(s"Auth token received: $sanitizedToken")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_8(): Unit = {
  val logger = Logger("FileProcessor")
  val fileContent = Source.fromFile(System.getProperty("user.input")).getLines().mkString("\n")
  
  // ok: scala-crlf-injection-logs
  logger.info(s"Processing file content: ${StringEscapeUtils.escapeJava(fileContent)}")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_9(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(this.getClass)
  val searchQuery = request.getQueryString("q").getOrElse("")
  
  // Using a constant string that doesn't contain external data
  // ok: scala-crlf-injection-logs
  logger.info("Search query received")
  
  // Log the actual query separately with sanitization
  if (searchQuery.nonEmpty) {
    logger.info(s"Query content: ${StringEscapeUtils.escapeJava(searchQuery)}")
  }
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_10(): Unit = {
  val logger = Logger("WebhookHandler")
  val process = Runtime.getRuntime.exec("curl https://api.external.com/webhook")
  val reader = new BufferedReader(new InputStreamReader(process.getInputStream))
  val webhookData = Iterator.continually(reader.readLine()).takeWhile(_ != null).mkString("\n")
  
  // ok: scala-crlf-injection-logs
  logger.info(s"Webhook data received: ${StringEscapeUtils.escapeJava(webhookData)}")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_11(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger("PaymentProcessor")
  val paymentDetails = request.body.asJson.map(json => (json \ "cardNumber").as[String]).getOrElse("")
  
  // ok: scala-crlf-injection-logs
  val lastFourDigits = paymentDetails.takeRight(4)
  logger.info(s"Last 4 digits of card: ${StringEscapeUtils.escapeJava(lastFourDigits)}")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_12(request: HttpServletRequest): Unit = {
  val logger = Logger("SessionManager")
  val sessionId = request.getSession.getId
  val referrer = request.getHeader("Referer")
  
  // ok: scala-crlf-injection-logs
  logger.info(s"Session ${StringEscapeUtils.escapeJava(sessionId)} created from referrer: ${StringEscapeUtils.escapeJava(referrer)}")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_13(): Unit = {
  val logger = LoggerFactory.getLogger("ConfigLoader")
  val configSource = Source.fromURL(new URL("https://config.example.org/app-config.json")).mkString
  
  // ok: scala-crlf-injection-logs
  logger.info("Configuration loaded successfully")
  
  // If we need to log specific parts, sanitize them individually
  Try(Json.parse(configSource)) match {
    case Success(json) => 
      val version = (json \ "version").asOpt[String].getOrElse("")
      logger.info(s"Config version: ${StringEscapeUtils.escapeJava(version)}")
    case Failure(e) => 
      logger.error(s"Failed to parse config: ${e.getMessage}")
  }
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_14(request: Request[AnyContent]): Unit = {
  val logger = Logger("UserRegistration")
  val email = request.body.asFormUrlEncoded.flatMap(_.get("email").map(_.head)).getOrElse("")
  val name = request.body.asFormUrlEncoded.flatMap(_.get("name").map(_.head)).getOrElse("")
  
  // ok: scala-crlf-injection-logs
  logger.info(s"New user registration: ${StringEscapeUtils.escapeJava(name)} (${StringEscapeUtils.escapeJava(email)})")
}
// {/fact}
// {fact rule=file-injection@v1.0 defects=0}

def good_case_15(request: HttpRequest): Unit = {
  val logger = LoggerFactory.getLogger("ErrorTracker")
  val errorMessage = request.entity.toString
  val clientIp = request.headers.find(_.name() == "X-Real-IP").map(_.value()).getOrElse("unknown")
  
  // ok: scala-crlf-injection-logs
  val sanitizedIp = StringEscapeUtils.escapeJava(clientIp)
  val sanitizedError = StringEscapeUtils.escapeJava(errorMessage)
  logger.error(s"Client error from $sanitizedIp: $sanitizedError")
}
// {/fact}