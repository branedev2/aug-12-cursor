import java.net.URI
import java.text.Normalizer
import scala.io.Source
import scala.collection.mutable.Map
import scala.collection.mutable.HashMap
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import play.api.mvc._
import play.api.http._
import scala.concurrent.Future
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.{HttpRequest, HttpResponse}

object ImproperUnicodeNormalizationExamples {

  // True Positives (Vulnerable Code)

  def bad_case_1(request: HttpServletRequest): Boolean = {
    val userInput = request.getParameter("username")
    val storedUsername = "café" // This could be from a database
    
    // ruleid: scala-improper-unicode-normalization
    userInput == storedUsername // Direct comparison without normalization
  }

  def bad_case_2(request: HttpServletRequest): Boolean = {
    val inputUri = new URI(request.getParameter("url"))
    val allowedUri = new URI("https://example.com/café")
    
    // ruleid: scala-improper-unicode-normalization
    inputUri.equals(allowedUri) // Comparing URIs without normalization
  }

  def bad_case_3(request: HttpServletRequest): Boolean = {
    val userInput = request.getParameter("name")
    val whitelist = List("José", "María", "François")
    
    // ruleid: scala-improper-unicode-normalization
    whitelist.contains(userInput) // List lookup without normalization
  }

  def bad_case_4(request: HttpServletRequest): String = {
    val path = request.getParameter("path")
    val allowedPaths = Map("résumé" -> "/documents", "café" -> "/menu")
    
    // ruleid: scala-improper-unicode-normalization
    allowedPaths.getOrElse(path, "/default") // Map lookup without normalization
  }

  def bad_case_5(request: HttpServletRequest): Boolean = {
    val username = request.getParameter("username")
    val storedUsername = Normalizer.normalize("café", Normalizer.Form.NFC)
    
    // ruleid: scala-improper-unicode-normalization
    username == storedUsername // Only one string is normalized
  }

  def bad_case_6(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val userInput = request.getParameter("text")
    val forbiddenWords = Set("naïve", "résumé")
    
    // ruleid: scala-improper-unicode-normalization
    if (forbiddenWords.exists(word => userInput.contains(word))) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN)
    }
  }

  def bad_case_7(): Boolean = {
    val fileName1 = "résumé.pdf"
    val fileName2 = "re\u0301sume\u0301.pdf" // Decomposed form
    
    // ruleid: scala-improper-unicode-normalization
    fileName1 == fileName2 // Direct comparison of differently normalized strings
  }

  def bad_case_8(request: HttpServletRequest): String = {
    val userInput = request.getParameter("search")
    val dictionary = HashMap[String, String]()
    dictionary.put("café", "Coffee shop")
    dictionary.put("naïve", "Lacking experience")
    
    // ruleid: scala-improper-unicode-normalization
    dictionary.getOrElse(userInput, "Not found")
  }

  def bad_case_9(request: HttpServletRequest): Boolean = {
    val inputPath = request.getParameter("path")
    val securePathPrefix = "/secure/área/"
    
    // ruleid: scala-improper-unicode-normalization
    inputPath.startsWith(securePathPrefix)
  }

  def bad_case_10(request: HttpServletRequest): Boolean = {
    val userRole = request.getParameter("role")
    val adminRole = "administratör"
    
    // ruleid: scala-improper-unicode-normalization
    if (userRole.equalsIgnoreCase(adminRole)) {
      true
    } else {
      false
    }
  }

  def bad_case_11(request: HttpServletRequest): Boolean = {
    val inputDomain = new URI(request.getParameter("domain")).getHost
    val allowedDomain = "café.example.com"
    
    // ruleid: scala-improper-unicode-normalization
    inputDomain == allowedDomain
  }

  def bad_case_12(request: HttpServletRequest): Boolean = {
    val userInput = request.getParameter("text")
    val normalizedInput = Normalizer.normalize(userInput, Normalizer.Form.NFD)
    val storedText = "café"
    
    // ruleid: scala-improper-unicode-normalization
    normalizedInput == storedText // Different normalization forms
  }

  def bad_case_13(action: Action[AnyContent]): Action[AnyContent] = {
    Action { request =>
      val username = request.getQueryString("username").getOrElse("")
      val validUser = "José"
      
      // ruleid: scala-improper-unicode-normalization
      if (username == validUser) {
        Results.Ok("Valid user")
      } else {
        Results.Forbidden("Invalid user")
      }
    }
  }

  def bad_case_14(request: HttpServletRequest): String = {
    val userInput = request.getParameter("category")
    val categories = Map("électronique" -> "Electronics", "vêtements" -> "Clothing")
    
    // ruleid: scala-improper-unicode-normalization
    categories.find(_._1.toLowerCase == userInput.toLowerCase).map(_._2).getOrElse("Unknown")
  }

  def bad_case_15(): Route = {
    path("user" / Segment) { username =>
      get {
        val storedUsername = "Zoë"
        
        // ruleid: scala-improper-unicode-normalization
        if (username == storedUsername) {
          complete("User found")
        } else {
          complete("User not found")
        }
      }
    }
  }

  // True Negatives (Safe Code)

  def good_case_1(request: HttpServletRequest): Boolean = {
    val userInput = request.getParameter("username")
    val storedUsername = "café" // This could be from a database
    
    // ok: scala-improper-unicode-normalization
    val normalizedInput = Normalizer.normalize(userInput, Normalizer.Form.NFC)
    val normalizedStored = Normalizer.normalize(storedUsername, Normalizer.Form.NFC)
    normalizedInput == normalizedStored
  }

  def good_case_2(request: HttpServletRequest): Boolean = {
    val inputUriStr = request.getParameter("url")
    val allowedUriStr = "https://example.com/café"
    
    // ok: scala-improper-unicode-normalization
    val normalizedInput = Normalizer.normalize(inputUriStr, Normalizer.Form.NFC)
    val normalizedAllowed = Normalizer.normalize(allowedUriStr, Normalizer.Form.NFC)
    new URI(normalizedInput).equals(new URI(normalizedAllowed))
  }

  def good_case_3(request: HttpServletRequest): Boolean = {
    val userInput = request.getParameter("name")
    val whitelist = List("José", "María", "François")
    
    // ok: scala-improper-unicode-normalization
    val normalizedInput = Normalizer.normalize(userInput, Normalizer.Form.NFC)
    val normalizedWhitelist = whitelist.map(name => Normalizer.normalize(name, Normalizer.Form.NFC))
    normalizedWhitelist.contains(normalizedInput)
  }

  def good_case_4(request: HttpServletRequest): String = {
    val path = request.getParameter("path")
    val normalizedPath = Normalizer.normalize(path, Normalizer.Form.NFC)
    
    val allowedPaths = Map(
      Normalizer.normalize("résumé", Normalizer.Form.NFC) -> "/documents",
      Normalizer.normalize("café", Normalizer.Form.NFC) -> "/menu"
    )
    
    // ok: scala-improper-unicode-normalization
    allowedPaths.getOrElse(normalizedPath, "/default")
  }

  def good_case_5(request: HttpServletRequest): Boolean = {
    val username = request.getParameter("username")
    val storedUsername = "café"
    
    // ok: scala-improper-unicode-normalization
    val normalizedUsername = Normalizer.normalize(username, Normalizer.Form.NFC)
    val normalizedStored = Normalizer.normalize(storedUsername, Normalizer.Form.NFC)
    normalizedUsername == normalizedStored
  }

  def good_case_6(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val userInput = request.getParameter("text")
    val forbiddenWords = Set("naïve", "résumé")
    
    // ok: scala-improper-unicode-normalization
    val normalizedInput = Normalizer.normalize(userInput, Normalizer.Form.NFC)
    val normalizedForbiddenWords = forbiddenWords.map(word => Normalizer.normalize(word, Normalizer.Form.NFC))
    
    if (normalizedForbiddenWords.exists(word => normalizedInput.contains(word))) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN)
    }
  }

  def good_case_7(): Boolean = {
    val fileName1 = "résumé.pdf"
    val fileName2 = "re\u0301sume\u0301.pdf" // Decomposed form
    
    // ok: scala-improper-unicode-normalization
    val normalizedName1 = Normalizer.normalize(fileName1, Normalizer.Form.NFC)
    val normalizedName2 = Normalizer.normalize(fileName2, Normalizer.Form.NFC)
    normalizedName1 == normalizedName2
  }

  def good_case_8(request: HttpServletRequest): String = {
    val userInput = request.getParameter("search")
    val normalizedInput = Normalizer.normalize(userInput, Normalizer.Form.NFC)
    
    val dictionary = HashMap[String, String]()
    dictionary.put(Normalizer.normalize("café", Normalizer.Form.NFC), "Coffee shop")
    dictionary.put(Normalizer.normalize("naïve", Normalizer.Form.NFC), "Lacking experience")
    
    // ok: scala-improper-unicode-normalization
    dictionary.getOrElse(normalizedInput, "Not found")
  }

  def good_case_9(request: HttpServletRequest): Boolean = {
    val inputPath = request.getParameter("path")
    val securePathPrefix = "/secure/área/"
    
    // ok: scala-improper-unicode-normalization
    val normalizedInput = Normalizer.normalize(inputPath, Normalizer.Form.NFC)
    val normalizedPrefix = Normalizer.normalize(securePathPrefix, Normalizer.Form.NFC)
    normalizedInput.startsWith(normalizedPrefix)
  }

  def good_case_10(request: HttpServletRequest): Boolean = {
    val userRole = request.getParameter("role")
    val adminRole = "administratör"
    
    // ok: scala-improper-unicode-normalization
    val normalizedUserRole = Normalizer.normalize(userRole, Normalizer.Form.NFC)
    val normalizedAdminRole = Normalizer.normalize(adminRole, Normalizer.Form.NFC)
    normalizedUserRole.equalsIgnoreCase(normalizedAdminRole)
  }

  def good_case_11(request: HttpServletRequest): Boolean = {
    val inputDomain = new URI(request.getParameter("domain")).getHost
    val allowedDomain = "café.example.com"
    
    // ok: scala-improper-unicode-normalization
    val normalizedInput = Normalizer.normalize(inputDomain, Normalizer.Form.NFC)
    val normalizedAllowed = Normalizer.normalize(allowedDomain, Normalizer.Form.NFC)
    normalizedInput == normalizedAllowed
  }

  def good_case_12(request: HttpServletRequest): Boolean = {
    val userInput = request.getParameter("text")
    val storedText = "café"
    
    // ok: scala-improper-unicode-normalization
    val normalizedInput = Normalizer.normalize(userInput, Normalizer.Form.NFC)
    val normalizedStored = Normalizer.normalize(storedText, Normalizer.Form.NFC)
    normalizedInput == normalizedStored
  }

  def good_case_13(action: Action[AnyContent]): Action[AnyContent] = {
    Action { request =>
      val username = request.getQueryString("username").getOrElse("")
      val validUser = "José"
      
      // ok: scala-improper-unicode-normalization
      val normalizedUsername = Normalizer.normalize(username, Normalizer.Form.NFC)
      val normalizedValidUser = Normalizer.normalize(validUser, Normalizer.Form.NFC)
      
      if (normalizedUsername == normalizedValidUser) {
        Results.Ok("Valid user")
      } else {
        Results.Forbidden("Invalid user")
      }
    }
  }

  def good_case_14(request: HttpServletRequest): String = {
    val userInput = request.getParameter("category")
    val normalizedInput = Normalizer.normalize(userInput.toLowerCase, Normalizer.Form.NFC)
    
    val categories = Map(
      Normalizer.normalize("électronique", Normalizer.Form.NFC).toLowerCase -> "Electronics",
      Normalizer.normalize("vêtements", Normalizer.Form.NFC).toLowerCase -> "Clothing"
    )
    
    // ok: scala-improper-unicode-normalization
    categories.getOrElse(normalizedInput, "Unknown")
  }

  def good_case_15(): Route = {
    path("user" / Segment) { username =>
      get {
        val storedUsername = "Zoë"
        
        // ok: scala-improper-unicode-normalization
        val normalizedInput = Normalizer.normalize(username, Normalizer.Form.NFC)
        val normalizedStored = Normalizer.normalize(storedUsername, Normalizer.Form.NFC)
        
        if (normalizedInput == normalizedStored) {
          complete("User found")
        } else {
          complete("User not found")
        }
      }
    }
  }
}