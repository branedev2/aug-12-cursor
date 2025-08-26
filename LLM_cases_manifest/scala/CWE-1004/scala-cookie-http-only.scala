import play.api.mvc._
import play.api.http.{HeaderNames, HttpVerbs}
import play.api.mvc.Cookie
import play.api.mvc.Results._
import play.api.mvc.request._
import play.api.mvc.BodyParsers
import play.api.http.HttpEntity
import play.api.libs.json._
import javax.inject.Inject
import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.duration._
import play.api.libs.ws._
import play.api.http.Status._
import akka.http.scaladsl.model.headers.{HttpCookie, `Set-Cookie`}
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.server.Route
import akka.http.scaladsl.model.HttpResponse
import akka.http.scaladsl.model.headers.RawHeader
// {fact rule=insecure-file-permissions@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(request: Request[AnyContent]): Result = {
  // ruleid: scala-cookie-http-only
  Ok("Login successful").withCookies(
    Cookie("sessionId", "12345", secure = true)
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_2(request: Request[AnyContent]): Result = {
  val userId = "user123"
  // ruleid: scala-cookie-http-only
  Ok("User profile").withCookies(
    Cookie(name = "userId", value = userId, maxAge = Some(3600))
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_3(request: Request[AnyContent]): Result = {
  val token = java.util.UUID.randomUUID().toString
  // ruleid: scala-cookie-http-only
  Ok("Authentication successful").withCookies(
    Cookie("authToken", token, secure = true, maxAge = Some(86400))
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_4(): Route = {
  path("login") {
    post {
      // ruleid: scala-cookie-http-only
      setCookie(HttpCookie("session", value = "abc123", secure = true)) {
        complete(StatusCodes.OK, "Logged in")
      }
    }
  }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_5(): Route = {
  path("preferences") {
    get {
      // ruleid: scala-cookie-http-only
      setCookie(HttpCookie("theme", value = "dark", maxAge = Some(30.days.toSeconds))) {
        complete(StatusCodes.OK, "Preferences saved")
      }
    }
  }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_6(request: Request[AnyContent]): Result = {
  val rememberMe = true
  // ruleid: scala-cookie-http-only
  Ok("Settings saved").withCookies(
    Cookie("rememberMe", rememberMe.toString, maxAge = Some(2592000))
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_7(): HttpResponse = {
  // ruleid: scala-cookie-http-only
  HttpResponse(
    status = StatusCodes.OK,
    headers = List(`Set-Cookie`(HttpCookie("tracking", "enabled")))
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_8(request: Request[AnyContent]): Result = {
  val cart = """{"items":[{"id":1,"qty":2}]}"""
  // ruleid: scala-cookie-http-only
  Ok("Cart updated").withCookies(
    Cookie("shoppingCart", cart, secure = true, maxAge = Some(3600))
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_9(): Route = {
  path("logout") {
    post {
      // ruleid: scala-cookie-http-only
      setCookie(HttpCookie("session", value = "", maxAge = Some(0L))) {
        complete(StatusCodes.OK, "Logged out")
      }
    }
  }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_10(request: Request[AnyContent]): Result = {
  // ruleid: scala-cookie-http-only
  Ok("Welcome").withCookies(
    Cookie("visited", "true", path = Some("/"), domain = Some("example.com"))
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_11(request: Request[AnyContent]): Result = {
  val language = "en-US"
  // ruleid: scala-cookie-http-only
  Ok("Language set").withCookies(
    Cookie("language", language, path = Some("/"), secure = request.secure)
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_12(): HttpResponse = {
  val cookie = HttpCookie(
    name = "analyticsId",
    value = "UA12345",
    secure = true
  )
  // ruleid: scala-cookie-http-only
  HttpResponse(
    status = StatusCodes.OK,
    headers = List(`Set-Cookie`(cookie))
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_13(request: Request[AnyContent]): Result = {
  // ruleid: scala-cookie-http-only
  Ok("Data saved").withCookies(
    Cookie("lastVisit", System.currentTimeMillis().toString)
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_14(): Route = {
  path("subscribe") {
    post {
      // ruleid: scala-cookie-http-only
      setCookie(HttpCookie("newsletter", value = "subscribed", maxAge = Some(365.days.toSeconds))) {
        complete(StatusCodes.OK, "Subscribed to newsletter")
      }
    }
  }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

def bad_case_15(request: Request[AnyContent]): Result = {
  val preferences = Map("notifications" -> "enabled", "darkMode" -> "true").toString
  // ruleid: scala-cookie-http-only
  Ok("Preferences updated").withCookies(
    Cookie("userPrefs", preferences, secure = true, maxAge = Some(30 * 24 * 60 * 60))
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

// True Negatives (Secure Code)

def good_case_1(request: Request[AnyContent]): Result = {
  // ok: scala-cookie-http-only
  Ok("Login successful").withCookies(
    Cookie("sessionId", "12345", secure = true, httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_2(request: Request[AnyContent]): Result = {
  val userId = "user123"
  // ok: scala-cookie-http-only
  Ok("User profile").withCookies(
    Cookie(name = "userId", value = userId, maxAge = Some(3600), httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_3(request: Request[AnyContent]): Result = {
  val token = java.util.UUID.randomUUID().toString
  // ok: scala-cookie-http-only
  Ok("Authentication successful").withCookies(
    Cookie("authToken", token, secure = true, httpOnly = true, maxAge = Some(86400))
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_4(): Route = {
  path("login") {
    post {
      // ok: scala-cookie-http-only
      setCookie(HttpCookie("session", value = "abc123", secure = true, httpOnly = true)) {
        complete(StatusCodes.OK, "Logged in")
      }
    }
  }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_5(): Route = {
  path("preferences") {
    get {
      // ok: scala-cookie-http-only
      setCookie(HttpCookie("theme", value = "dark", maxAge = Some(30.days.toSeconds), httpOnly = true)) {
        complete(StatusCodes.OK, "Preferences saved")
      }
    }
  }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_6(request: Request[AnyContent]): Result = {
  val rememberMe = true
  // ok: scala-cookie-http-only
  Ok("Settings saved").withCookies(
    Cookie("rememberMe", rememberMe.toString, maxAge = Some(2592000), httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_7(): HttpResponse = {
  // ok: scala-cookie-http-only
  HttpResponse(
    status = StatusCodes.OK,
    headers = List(`Set-Cookie`(HttpCookie("tracking", "enabled", httpOnly = true)))
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_8(request: Request[AnyContent]): Result = {
  val cart = """{"items":[{"id":1,"qty":2}]}"""
  // ok: scala-cookie-http-only
  Ok("Cart updated").withCookies(
    Cookie("shoppingCart", cart, secure = true, httpOnly = true, maxAge = Some(3600))
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_9(): Route = {
  path("logout") {
    post {
      // ok: scala-cookie-http-only
      setCookie(HttpCookie("session", value = "", maxAge = Some(0L), httpOnly = true)) {
        complete(StatusCodes.OK, "Logged out")
      }
    }
  }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_10(request: Request[AnyContent]): Result = {
  // ok: scala-cookie-http-only
  Ok("Welcome").withCookies(
    Cookie("visited", "true", path = Some("/"), domain = Some("example.com"), httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_11(request: Request[AnyContent]): Result = {
  val language = "en-US"
  // ok: scala-cookie-http-only
  Ok("Language set").withCookies(
    Cookie("language", language, path = Some("/"), secure = request.secure, httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_12(): HttpResponse = {
  val cookie = HttpCookie(
    name = "analyticsId",
    value = "UA12345",
    secure = true,
    httpOnly = true
  )
  // ok: scala-cookie-http-only
  HttpResponse(
    status = StatusCodes.OK,
    headers = List(`Set-Cookie`(cookie))
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_13(request: Request[AnyContent]): Result = {
  // ok: scala-cookie-http-only
  Ok("Data saved").withCookies(
    Cookie("lastVisit", System.currentTimeMillis().toString, httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_14(): Route = {
  path("subscribe") {
    post {
      // ok: scala-cookie-http-only
      setCookie(HttpCookie("newsletter", value = "subscribed", maxAge = Some(365.days.toSeconds), httpOnly = true)) {
        complete(StatusCodes.OK, "Subscribed to newsletter")
      }
    }
  }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

def good_case_15(request: Request[AnyContent]): Result = {
  val preferences = Map("notifications" -> "enabled", "darkMode" -> "true").toString
  // Using JavaScript-accessible cookie for client-side preferences is acceptable
  // This is a legitimate use case where httpOnly is not needed
  // ok: scala-cookie-http-only
  Ok("Preferences updated").withCookies(
    Cookie("clientPrefs", preferences, secure = true)
  )
}
// {/fact}