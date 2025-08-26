// File: ImproperArrayIndexCheckExamples.scala

import scala.collection.mutable.ArrayBuffer
import scala.io.Source
import scala.util.Try
import play.api.mvc._
import play.api.http._
import play.api.libs.json._
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global

object ImproperArrayIndexCheckExamples {

  // True Positives (Vulnerable Code)

  def bad_case_1(request: Request[AnyContent]): String = {
    val userInput = request.getQueryString("input").getOrElse("")
    val allowedValues = List("admin", "user", "guest")
    
    // ruleid: scala-improper-array-index-check
    if (allowedValues.indexOf(userInput) > 0) {
      "User has special permissions"
    } else {
      "Access denied"
    }
  }

  def bad_case_2(request: Request[AnyContent]): Boolean = {
    val username = request.body.asFormUrlEncoded.flatMap(_.get("username").flatMap(_.headOption)).getOrElse("")
    val validUsers = Array("admin", "root", "system", "user")
    
    // ruleid: scala-improper-array-index-check
    validUsers.indexOf(username) > 0
  }

  def bad_case_3(): Unit = {
    val fruits = Vector("apple", "banana", "cherry", "date")
    val searchTerm = "apple"
    
    // ruleid: scala-improper-array-index-check
    if (fruits.indexOf(searchTerm) > 0) {
      println(s"Found $searchTerm at position other than first")
    } else {
      println(s"$searchTerm not found or is the first element")
    }
  }

  def bad_case_4(request: Request[AnyContent]): String = {
    val headerValue = request.headers.get("X-Custom-Header").getOrElse("")
    val allowedHeaders = List("Content-Type", "Authorization", "X-API-Key")
    
    // ruleid: scala-improper-array-index-check
    if (allowedHeaders.indexOf(headerValue) > 0) {
      "Header is allowed but not the first one"
    } else {
      "Header not allowed or is the first one"
    }
  }

  def bad_case_5(request: Request[AnyContent]): Boolean = {
    val userRole = request.session.get("role").getOrElse("")
    val adminRoles = ArrayBuffer("superadmin", "admin", "moderator")
    
    // ruleid: scala-improper-array-index-check
    adminRoles.indexOf(userRole) > 0
  }

  def bad_case_6(): Unit = {
    val data = Map("key1" -> "value1", "key2" -> "value2")
    val keys = data.keys.toList
    val searchKey = "key1"
    
    // ruleid: scala-improper-array-index-check
    if (keys.indexOf(searchKey) > 0) {
      println("Key found but not at the beginning")
    } else {
      println("Key not found or is the first key")
    }
  }

  def bad_case_7(request: Request[AnyContent]): String = {
    val cookieValue = request.cookies.get("preference").map(_.value).getOrElse("")
    val validPreferences = Seq("dark", "light", "system")
    
    // ruleid: scala-improper-array-index-check
    validPreferences.indexOf(cookieValue) > 0 match {
      case true => "Valid non-default preference"
      case false => "Invalid or default preference"
    }
  }

  def bad_case_8(): Unit = {
    val commandArgs = Array("--help", "--version", "--debug", "--quiet")
    val arg = "--help"
    
    // ruleid: scala-improper-array-index-check
    commandArgs.indexOf(arg) > 0 match {
      case true => println("Non-primary argument")
      case false => println("Primary argument or not found")
    }
  }

  def bad_case_9(request: Request[AnyContent]): Boolean = {
    val jsonBody = request.body.asJson.getOrElse(Json.obj())
    val requiredFields = List("username", "password", "email")
    val providedFields = (jsonBody \ "fields").as[List[String]]
    
    // ruleid: scala-improper-array-index-check
    requiredFields.forall(field => providedFields.indexOf(field) > 0)
  }

  def bad_case_10(): String = {
    val config = Map("host" -> "localhost", "port" -> "8080", "protocol" -> "https")
    val secureProtocols = List("https", "sftp", "ssh")
    val protocol = config.getOrElse("protocol", "")
    
    // ruleid: scala-improper-array-index-check
    if (secureProtocols.indexOf(protocol) > 0) {
      "Using non-default secure protocol"
    } else {
      "Using default protocol or insecure protocol"
    }
  }

  def bad_case_11(request: Request[AnyContent]): Unit = {
    val userAgent = request.headers.get("User-Agent").getOrElse("")
    val supportedBrowsers = Vector("Chrome", "Firefox", "Safari", "Edge")
    
    // ruleid: scala-improper-array-index-check
    val browserSupported = supportedBrowsers.exists(browser => 
      userAgent.indexOf(browser) > 0
    )
    
    println(s"Browser supported: $browserSupported")
  }

  def bad_case_12(): Boolean = {
    val permissions = Array("read", "write", "execute", "delete")
    val userPermission = "read"
    
    // ruleid: scala-improper-array-index-check
    permissions.indexOf(userPermission) > 0
  }

  def bad_case_13(request: Request[AnyContent]): String = {
    val path = request.path
    val restrictedPaths = List("/admin", "/config", "/users", "/api")
    
    // ruleid: scala-improper-array-index-check
    if (restrictedPaths.exists(p => path.indexOf(p) > 0)) {
      "Path contains restricted segment but not at the beginning"
    } else {
      "Path is safe or has restricted segment at the beginning"
    }
  }

  def bad_case_14(): Unit = {
    val tags = List("important", "urgent", "normal", "low")
    val messageTag = "important"
    
    // ruleid: scala-improper-array-index-check
    val priority = if (tags.indexOf(messageTag) > 0) "Not highest priority" else "Highest priority or not found"
    println(priority)
  }

  def bad_case_15(request: Request[AnyContent]): Boolean = {
    val acceptHeader = request.headers.get("Accept").getOrElse("")
    val supportedTypes = Seq("application/json", "text/plain", "application/xml")
    
    // ruleid: scala-improper-array-index-check
    supportedTypes.indexOf(acceptHeader) > 0
  }

  // True Negatives (Safe Code)

  def good_case_1(request: Request[AnyContent]): String = {
    val userInput = request.getQueryString("input").getOrElse("")
    val allowedValues = List("admin", "user", "guest")
    
    // ok: scala-improper-array-index-check
    if (allowedValues.indexOf(userInput) >= 0) {
      "User has permissions"
    } else {
      "Access denied"
    }
  }

  def good_case_2(request: Request[AnyContent]): Boolean = {
    val username = request.body.asFormUrlEncoded.flatMap(_.get("username").flatMap(_.headOption)).getOrElse("")
    val validUsers = Array("admin", "root", "system", "user")
    
    // ok: scala-improper-array-index-check
    validUsers.indexOf(username) > -1
  }

  def good_case_3(): Unit = {
    val fruits = Vector("apple", "banana", "cherry", "date")
    val searchTerm = "apple"
    
    // ok: scala-improper-array-index-check
    if (fruits.indexOf(searchTerm) != -1) {
      println(s"Found $searchTerm")
    } else {
      println(s"$searchTerm not found")
    }
  }

  def good_case_4(request: Request[AnyContent]): String = {
    val headerValue = request.headers.get("X-Custom-Header").getOrElse("")
    val allowedHeaders = List("Content-Type", "Authorization", "X-API-Key")
    
    // ok: scala-improper-array-index-check
    if (allowedHeaders.contains(headerValue)) {
      "Header is allowed"
    } else {
      "Header not allowed"
    }
  }

  def good_case_5(request: Request[AnyContent]): Boolean = {
    val userRole = request.session.get("role").getOrElse("")
    val adminRoles = ArrayBuffer("superadmin", "admin", "moderator")
    
    // ok: scala-improper-array-index-check
    adminRoles.indexOf(userRole) >= 0
  }

  def good_case_6(): Unit = {
    val data = Map("key1" -> "value1", "key2" -> "value2")
    val keys = data.keys.toList
    val searchKey = "key1"
    
    // ok: scala-improper-array-index-check
    if (keys.indexOf(searchKey) > -1) {
      println("Key found")
    } else {
      println("Key not found")
    }
  }

  def good_case_7(request: Request[AnyContent]): String = {
    val cookieValue = request.cookies.get("preference").map(_.value).getOrElse("")
    val validPreferences = Seq("dark", "light", "system")
    
    // ok: scala-improper-array-index-check
    validPreferences.contains(cookieValue) match {
      case true => "Valid preference"
      case false => "Invalid preference"
    }
  }

  def good_case_8(): Unit = {
    val commandArgs = Array("--help", "--version", "--debug", "--quiet")
    val arg = "--help"
    
    // ok: scala-improper-array-index-check
    if (commandArgs.indexOf(arg) == 0) {
      println("This is the primary argument")
    } else if (commandArgs.indexOf(arg) > 0) {
      println("This is a secondary argument")
    } else {
      println("Argument not found")
    }
  }

  def good_case_9(request: Request[AnyContent]): Boolean = {
    val jsonBody = request.body.asJson.getOrElse(Json.obj())
    val requiredFields = List("username", "password", "email")
    val providedFields = (jsonBody \ "fields").as[List[String]]
    
    // ok: scala-improper-array-index-check
    requiredFields.forall(field => providedFields.indexOf(field) >= 0)
  }

  def good_case_10(): String = {
    val config = Map("host" -> "localhost", "port" -> "8080", "protocol" -> "https")
    val secureProtocols = List("https", "sftp", "ssh")
    val protocol = config.getOrElse("protocol", "")
    
    // ok: scala-improper-array-index-check
    if (secureProtocols.contains(protocol)) {
      "Using secure protocol"
    } else {
      "Using insecure protocol"
    }
  }

  def good_case_11(request: Request[AnyContent]): Unit = {
    val userAgent = request.headers.get("User-Agent").getOrElse("")
    val supportedBrowsers = Vector("Chrome", "Firefox", "Safari", "Edge")
    
    // ok: scala-improper-array-index-check
    val browserSupported = supportedBrowsers.exists(browser => 
      userAgent.indexOf(browser) != -1
    )
    
    println(s"Browser supported: $browserSupported")
  }

  def good_case_12(): Boolean = {
    val permissions = Array("read", "write", "execute", "delete")
    val userPermission = "read"
    
    // ok: scala-improper-array-index-check
    permissions.indexOf(userPermission) != -1
  }

  def good_case_13(request: Request[AnyContent]): String = {
    val path = request.path
    val restrictedPaths = List("/admin", "/config", "/users", "/api")
    
    // ok: scala-improper-array-index-check
    if (restrictedPaths.exists(p => path.indexOf(p) >= 0)) {
      "Path contains restricted segment"
    } else {
      "Path is safe"
    }
  }

  def good_case_14(): Unit = {
    val tags = List("important", "urgent", "normal", "low")
    val messageTag = "important"
    
    // ok: scala-improper-array-index-check
    val priority = if (tags.indexOf(messageTag) == 0) "Highest priority" else if (tags.indexOf(messageTag) > 0) "Lower priority" else "Not found"
    println(priority)
  }

  def good_case_15(request: Request[AnyContent]): Boolean = {
    val acceptHeader = request.headers.get("Accept").getOrElse("")
    val supportedTypes = Seq("application/json", "text/plain", "application/xml")
    
    // ok: scala-improper-array-index-check
    supportedTypes.indexOf(acceptHeader) >= 0
  }
}