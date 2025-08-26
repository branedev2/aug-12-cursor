import javax.servlet.http.{HttpServletRequest, HttpServletResponse, HttpSession}
import org.apache.commons.lang3.StringEscapeUtils
import play.api.mvc._
import scala.collection.mutable.Map
import scala.util.{Try, Success, Failure}
import play.api.mvc.{Action, Controller, Request, AnyContent}
import play.api.http.{Status, HeaderNames}
// {fact rule=resource-leak@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val session = request.getSession()
  val userInput = request.getParameter("userInput")
  
  // ruleid: scala-trust-boundary-violation
  session.setAttribute(userInput, "someValue")
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=1}

def bad_case_2(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val session = request.getSession()
  val userInput = request.getParameter("userInput")
  
  // ruleid: scala-trust-boundary-violation
  session.setAttribute("userAttribute", userInput)
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=1}

def bad_case_3(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val session = request.getSession()
  val userName = request.getParameter("username")
  val role = request.getParameter("role")
  
  // ruleid: scala-trust-boundary-violation
  session.setAttribute(userName, role)
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=1}

def bad_case_4(request: HttpServletRequest): Unit = {
  val session = request.getSession(true)
  val userPreference = request.getParameter("preference")
  val prefValue = request.getParameter("value")
  
  // ruleid: scala-trust-boundary-violation
  session.setAttribute(s"user_${userPreference}", prefValue)
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=1}

def bad_case_5(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val headerValue = request.getHeader("X-Custom-Header")
  
  // ruleid: scala-trust-boundary-violation
  session.setAttribute("headerAttribute", headerValue)
}
// {/fact}

class BadController6 extends Controller {
  def bad_case_6() = Action { request =>
    val userInput = request.getQueryString("key").getOrElse("")
    val value = request.getQueryString("value").getOrElse("")
    
    // ruleid: scala-trust-boundary-violation
    request.session + (userInput -> value)
    
    Ok("Session updated")
  }
}

class BadController7 extends Controller {
  def bad_case_7() = Action { request =>
    val userId = request.body.asFormUrlEncoded.flatMap(_.get("userId").flatMap(_.headOption)).getOrElse("")
    
    // ruleid: scala-trust-boundary-violation
    request.session + ("userId" -> userId)
    
    Ok("User ID stored in session")
  }
}
// {fact rule=resource-leak@v1.0 defects=1}

def bad_case_8(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val cookieValue = request.getCookies().find(_.getName == "userPref").map(_.getValue).getOrElse("")
  
  // ruleid: scala-trust-boundary-violation
  session.setAttribute("cookiePref", cookieValue)
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=1}

def bad_case_9(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val userInput = request.getParameter("input")
  val processedInput = userInput.toLowerCase() // Simple processing doesn't make it safe
  
  // ruleid: scala-trust-boundary-violation
  session.setAttribute("processedInput", processedInput)
}
// {/fact}

class BadController10 extends Controller {
  def bad_case_10() = Action { request =>
    val sessionMap = Map[String, String]()
    
    request.queryString.foreach { case (key, values) =>
      if (values.nonEmpty) {
        // ruleid: scala-trust-boundary-violation
        request.session + (key -> values.head)
      }
    }
    
    Ok("All query parameters stored in session")
  }
}
// {fact rule=resource-leak@v1.0 defects=1}

def bad_case_11(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val referer = request.getHeader("Referer")
  
  // ruleid: scala-trust-boundary-violation
  session.setAttribute("lastPage", referer)
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=1}

def bad_case_12(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val userAgent = request.getHeader("User-Agent")
  
  // ruleid: scala-trust-boundary-violation
  session.setAttribute("userAgent", userAgent)
}
// {/fact}

class BadController13 extends Controller {
  def bad_case_13() = Action { request =>
    val jsonBody = request.body.asJson.getOrElse(play.api.libs.json.Json.obj())
    val username = (jsonBody \ "username").asOpt[String].getOrElse("")
    
    // ruleid: scala-trust-boundary-violation
    request.session + ("username" -> username)
    
    Ok("Username stored in session")
  }
}
// {fact rule=resource-leak@v1.0 defects=1}

def bad_case_14(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val paramNames = request.getParameterNames
  
  while (paramNames.hasMoreElements) {
    val paramName = paramNames.nextElement().toString
    val paramValue = request.getParameter(paramName)
    
    // ruleid: scala-trust-boundary-violation
    session.setAttribute(paramName, paramValue)
  }
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=1}

def bad_case_15(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val requestURI = request.getRequestURI
  
  // ruleid: scala-trust-boundary-violation
  session.setAttribute("lastRequestURI", requestURI)
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=0}

// True Negative Examples (Secure Code)

def good_case_1(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val session = request.getSession()
  val userInput = request.getParameter("userInput")
  
  // Validate input against an allowlist
  val validAttributes = Set("preference", "theme", "language")
  
  // ok: scala-trust-boundary-violation
  if (validAttributes.contains(userInput)) {
    session.setAttribute(userInput, "someValue")
  }
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=0}

def good_case_2(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val session = request.getSession()
  val userInput = request.getParameter("userInput")
  
  // Sanitize the input before using it
  // ok: scala-trust-boundary-violation
  val sanitizedInput = StringEscapeUtils.escapeHtml4(userInput)
  session.setAttribute("userAttribute", sanitizedInput)
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=0}

def good_case_3(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val session = request.getSession()
  val userName = request.getParameter("username")
  
  // Use a fixed attribute name instead of user input
  // ok: scala-trust-boundary-violation
  session.setAttribute("username", StringEscapeUtils.escapeHtml4(userName))
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=0}

def good_case_4(request: HttpServletRequest): Unit = {
  val session = request.getSession(true)
  val userPreference = request.getParameter("preference")
  val prefValue = request.getParameter("value")
  
  // Validate against allowlist before using
  val validPreferences = Set("theme", "fontSize", "colorScheme")
  
  // ok: scala-trust-boundary-violation
  if (validPreferences.contains(userPreference)) {
    session.setAttribute(s"user_${userPreference}", StringEscapeUtils.escapeHtml4(prefValue))
  }
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=0}

def good_case_5(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val headerValue = request.getHeader("X-Custom-Header")
  
  // ok: scala-trust-boundary-violation
  val sanitizedHeader = StringEscapeUtils.escapeHtml4(headerValue)
  session.setAttribute("headerAttribute", sanitizedHeader)
}
// {/fact}

class GoodController6 extends Controller {
  def good_case_6() = Action { request =>
    val value = request.getQueryString("value").getOrElse("")
    
    // Using a fixed key instead of user input
    // ok: scala-trust-boundary-violation
    request.session + ("fixedKey" -> StringEscapeUtils.escapeHtml4(value))
    
    Ok("Session updated safely")
  }
}

class GoodController7 extends Controller {
  def good_case_7() = Action { request =>
    val userId = request.body.asFormUrlEncoded.flatMap(_.get("userId").flatMap(_.headOption)).getOrElse("")
    
    // Validate userId format (e.g., ensure it's numeric)
    // ok: scala-trust-boundary-violation
    if (userId.matches("\\d+")) {
      request.session + ("userId" -> userId)
      Ok("Valid user ID stored in session")
    } else {
      BadRequest("Invalid user ID")
    }
  }
}
// {fact rule=resource-leak@v1.0 defects=0}

def good_case_8(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val cookieValue = request.getCookies().find(_.getName == "userPref").map(_.getValue).getOrElse("")
  
  // Validate cookie value against allowlist
  val validValues = Set("light", "dark", "system")
  
  // ok: scala-trust-boundary-violation
  if (validValues.contains(cookieValue)) {
    session.setAttribute("cookiePref", cookieValue)
  } else {
    session.setAttribute("cookiePref", "system") // Default safe value
  }
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=0}

def good_case_9(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val userInput = request.getParameter("input")
  
  // ok: scala-trust-boundary-violation
  val sanitizedInput = StringEscapeUtils.escapeHtml4(userInput)
  session.setAttribute("processedInput", sanitizedInput)
}
// {/fact}

class GoodController10 extends Controller {
  def good_case_10() = Action { request =>
    val allowedParams = Set("theme", "language", "timezone")
    
    // ok: scala-trust-boundary-violation
    val safeSession = request.queryString.collect {
      case (key, values) if allowedParams.contains(key) && values.nonEmpty => 
        key -> StringEscapeUtils.escapeHtml4(values.head)
    }.foldLeft(request.session) { case (session, (key, value)) =>
      session + (key -> value)
    }
    
    Ok("Safe parameters stored in session")
  }
}
// {fact rule=resource-leak@v1.0 defects=0}

def good_case_11(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val referer = request.getHeader("Referer")
  
  // ok: scala-trust-boundary-violation
  Try {
    val url = new java.net.URL(referer)
    // Only store referer if it's from our domain
    if (url.getHost == "example.com") {
      session.setAttribute("lastPage", StringEscapeUtils.escapeHtml4(referer))
    }
  }.getOrElse {
    // Invalid URL, don't store it
  }
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=0}

def good_case_12(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val userAgent = request.getHeader("User-Agent")
  
  // ok: scala-trust-boundary-violation
  val sanitizedUserAgent = StringEscapeUtils.escapeHtml4(userAgent)
  session.setAttribute("userAgent", sanitizedUserAgent)
}
// {/fact}

class GoodController13 extends Controller {
  def good_case_13() = Action { request =>
    val jsonBody = request.body.asJson.getOrElse(play.api.libs.json.Json.obj())
    val username = (jsonBody \ "username").asOpt[String].getOrElse("")
    
    // ok: scala-trust-boundary-violation
    val sanitizedUsername = StringEscapeUtils.escapeHtml4(username)
    request.session + ("username" -> sanitizedUsername)
    
    Ok("Username safely stored in session")
  }
}
// {fact rule=resource-leak@v1.0 defects=0}

def good_case_14(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val paramNames = request.getParameterNames
  val allowedParams = Set("theme", "language", "timezone")
  
  while (paramNames.hasMoreElements) {
    val paramName = paramNames.nextElement().toString
    val paramValue = request.getParameter(paramName)
    
    // ok: scala-trust-boundary-violation
    if (allowedParams.contains(paramName)) {
      session.setAttribute(paramName, StringEscapeUtils.escapeHtml4(paramValue))
    }
  }
}
// {/fact}
// {fact rule=resource-leak@v1.0 defects=0}

def good_case_15(request: HttpServletRequest): Unit = {
  val session = request.getSession()
  val requestURI = request.getRequestURI
  
  // ok: scala-trust-boundary-violation
  val sanitizedURI = StringEscapeUtils.escapeHtml4(requestURI)
  session.setAttribute("lastRequestURI", sanitizedURI)
}
// {/fact}