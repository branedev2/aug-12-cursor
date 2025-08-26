import scala.io.Source
import org.slf4j.{Logger, LoggerFactory}
import play.api.mvc._
import play.api.http.HttpEntity
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.{HttpRequest, HttpResponse, StatusCodes}
import org.apache.logging.log4j.{LogManager, Logger => Log4jLogger}
import ch.qos.logback.classic.{Logger => LogbackLogger}
import com.typesafe.scalalogging.LazyLogging
import scala.concurrent.Future
import scala.util.{Success, Failure}
import java.net.URLEncoder
import org.owasp.encoder.Encode
import play.api.libs.json.Json
import scala.collection.mutable.StringBuilder
// {fact rule=ldap-injection@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val username = request.getQueryString("username").getOrElse("")
  
  // ruleid: scala-log-injection-ide
  logger.info(s"User login attempt: $username")
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_2(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger("SecurityLogger")
  val searchTerm = request.body.asFormUrlEncoded.get("search").headOption.getOrElse("")
  
  // ruleid: scala-log-injection-ide
  logger.error(s"Failed to find results for: $searchTerm")
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_3(request: HttpRequest): Unit = {
  val logger = LogManager.getLogger(getClass)
  val ipAddress = request.headers.find(_.name == "X-Forwarded-For").map(_.value).getOrElse("unknown")
  
  // ruleid: scala-log-injection-ide
  logger.warn("Access attempt from IP: " + ipAddress)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_4(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val userAgent = request.headers.get("User-Agent").getOrElse("")
  
  // ruleid: scala-log-injection-ide
  logger.debug(f"Request from user agent: $userAgent")
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_5(): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val requestBody = Source.fromURL("http://example.com/api/data").mkString
  
  // ruleid: scala-log-injection-ide
  logger.info("Received data: " + requestBody)
}
// {/fact}

class BadController extends Controller with LazyLogging {
  def bad_case_6(request: Request[AnyContent]): Action[AnyContent] = Action { request =>
    val email = request.body.asJson.get("email").as[String]
    
    // ruleid: scala-log-injection-ide
    logger.info(s"Processing request for email: $email")
    Ok("Request processed")
  }
}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_7(request: HttpRequest): Unit = {
  val log4jLogger = LogManager.getLogger("AuditLogger")
  val sessionId = request.cookies.find(_.name == "sessionId").map(_.value).getOrElse("")
  
  // ruleid: scala-log-injection-ide
  log4jLogger.info("User session: {}", sessionId)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_8(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val errorMessage = request.getQueryString("error").getOrElse("")
  
  // ruleid: scala-log-injection-ide
  logger.error(s"Application error occurred: $errorMessage")
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_9(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val comments = request.body.asFormUrlEncoded.get("comments").headOption.getOrElse("")
  
  // ruleid: scala-log-injection-ide
  logger.info("User submitted comment: " + comments)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_10(request: HttpRequest): Unit = {
  val logger = LogManager.getLogger(getClass)
  val referer = request.headers.find(_.name == "Referer").map(_.value).getOrElse("")
  
  // ruleid: scala-log-injection-ide
  logger.info(s"Request referred from: $referer")
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_11(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val jsonData = request.body.asJson.get.toString()
  
  // ruleid: scala-log-injection-ide
  logger.warn(f"Processing potentially malformed JSON: $jsonData")
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_12(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val token = request.headers.get("Authorization").getOrElse("").replaceAll("Bearer ", "")
  
  // ruleid: scala-log-injection-ide
  logger.debug("Authentication attempt with token: " + token)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_13(): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val queryParams = Source.fromURL("http://example.com/api/data?query=test").mkString
  
  // ruleid: scala-log-injection-ide
  logger.info(s"API response with query params: $queryParams")
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_14(request: HttpRequest): Unit = {
  val logger = LogManager.getLogger("SecurityAudit")
  val contentType = request.headers.find(_.name == "Content-Type").map(_.value).getOrElse("")
  
  // ruleid: scala-log-injection-ide
  logger.info("Request content type: {}", contentType)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

def bad_case_15(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val fileNames = request.body.asMultipartFormData.get.files.map(_.filename).mkString(", ")
  
  // ruleid: scala-log-injection-ide
  logger.info(s"Uploaded files: $fileNames")
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// True Negative Examples (Safe Code)

def good_case_1(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val username = request.getQueryString("username").getOrElse("")
  
  // ok: scala-log-injection-ide
  logger.info("User login attempt: {}", username)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_2(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger("SecurityLogger")
  val searchTerm = request.body.asFormUrlEncoded.get("search").headOption.getOrElse("")
  
  // ok: scala-log-injection-ide
  logger.error("Failed to find results for: {}", searchTerm)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_3(request: HttpRequest): Unit = {
  val logger = LogManager.getLogger(getClass)
  val ipAddress = request.headers.find(_.name == "X-Forwarded-For").map(_.value).getOrElse("unknown")
  
  // ok: scala-log-injection-ide
  logger.warn("Access attempt from IP: {}", ipAddress)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_4(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val userAgent = request.headers.get("User-Agent").getOrElse("")
  val sanitizedUserAgent = Encode.forHtml(userAgent)
  
  // ok: scala-log-injection-ide
  logger.debug("Request from user agent: {}", sanitizedUserAgent)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_5(): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val requestBody = Source.fromURL("http://example.com/api/data").mkString
  
  // ok: scala-log-injection-ide
  logger.info("Received data: {}", requestBody)
}
// {/fact}

class GoodController extends Controller with LazyLogging {
  def good_case_6(request: Request[AnyContent]): Action[AnyContent] = Action { request =>
    val email = request.body.asJson.get("email").as[String]
    
    // ok: scala-log-injection-ide
    logger.info("Processing request for email: {}", email)
    Ok("Request processed")
  }
}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_7(request: HttpRequest): Unit = {
  val log4jLogger = LogManager.getLogger("AuditLogger")
  val sessionId = request.cookies.find(_.name == "sessionId").map(_.value).getOrElse("")
  val sanitizedSessionId = sessionId.replaceAll("[\\r\\n]", "")
  
  // ok: scala-log-injection-ide
  log4jLogger.info("User session: {}", sanitizedSessionId)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_8(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val errorMessage = request.getQueryString("error").getOrElse("")
  
  // Using a whitelist approach to validate input
  val allowedErrors = Set("timeout", "not_found", "permission_denied")
  val safeErrorMessage = if (allowedErrors.contains(errorMessage)) errorMessage else "invalid_error"
  
  // ok: scala-log-injection-ide
  logger.error("Application error occurred: {}", safeErrorMessage)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_9(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val comments = request.body.asFormUrlEncoded.get("comments").headOption.getOrElse("")
  
  // Sanitize the input by removing any control characters
  val sanitizedComments = comments.replaceAll("[\\r\\n]", " ")
  
  // ok: scala-log-injection-ide
  logger.info("User submitted comment: {}", sanitizedComments)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_10(request: HttpRequest): Unit = {
  val logger = LogManager.getLogger(getClass)
  val referer = request.headers.find(_.name == "Referer").map(_.value).getOrElse("")
  
  // ok: scala-log-injection-ide
  logger.info("Request referred from: {}", referer)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_11(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val jsonData = request.body.asJson.get
  
  // Extract only needed fields instead of logging the entire JSON
  val requestId = (jsonData \ "id").asOpt[String].getOrElse("unknown")
  
  // ok: scala-log-injection-ide
  logger.warn("Processing request ID: {}", requestId)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_12(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val hasToken = request.headers.get("Authorization").isDefined
  
  // ok: scala-log-injection-ide
  logger.debug("Authentication attempt with token present: {}", hasToken)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_13(): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val queryParams = Source.fromURL("http://example.com/api/data?query=test").mkString
  
  // Sanitize by encoding the URL
  val encodedParams = URLEncoder.encode(queryParams, "UTF-8")
  
  // ok: scala-log-injection-ide
  logger.info("API response with query params: {}", encodedParams)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_14(request: HttpRequest): Unit = {
  val logger = LogManager.getLogger("SecurityAudit")
  val contentType = request.headers.find(_.name == "Content-Type").map(_.value).getOrElse("")
  
  // Validate content type against allowed list
  val validContentTypes = Set("application/json", "application/xml", "text/plain")
  val safeContentType = if (validContentTypes.contains(contentType)) contentType else "invalid"
  
  // ok: scala-log-injection-ide
  logger.info("Request content type: {}", safeContentType)
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

def good_case_15(request: Request[AnyContent]): Unit = {
  val logger = LoggerFactory.getLogger(getClass)
  val fileCount = request.body.asMultipartFormData.get.files.size
  
  // Log only the count, not the actual filenames
  // ok: scala-log-injection-ide
  logger.info("Number of uploaded files: {}", fileCount)
}
// {/fact}