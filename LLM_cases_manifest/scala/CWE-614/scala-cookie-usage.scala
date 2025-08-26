import play.api.mvc._
import play.api.http.{HeaderNames, HttpVerbs}
import play.api.libs.json.Json
import javax.inject.Inject
import scala.concurrent.{ExecutionContext, Future}
import play.api.mvc.Cookie
import play.api.mvc.DiscardingCookie
import play.api.mvc.Results._
import play.api.http.HttpEntity
import play.api.mvc.request.RequestTarget
import play.api.mvc.Result
import play.api.http.Status
import play.api.http.Writeable
import play.api.mvc.AnyContent
import play.api.mvc.BodyParser
import play.api.mvc.Headers
import play.api.mvc.Session
import play.api.mvc.Flash
import javax.inject.Singleton
import play.api.routing.Router
import play.api.http.FileMimeTypes
import play.api.i18n.{Langs, MessagesApi}
import play.api.Environment
import play.api.mvc.RequestHeader
import play.api.mvc.CookieHeaderEncoding
// {fact rule=insecure-cookie@v1.0 defects=1}

// True Positives (Vulnerable Code Examples)

def bad_case_1(request: Request[AnyContent]): Result = {
  // ruleid: scala-cookie-usage
  Ok("Login successful").withCookies(
    Cookie("sessionId", "12345abcde")
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_2(request: Request[AnyContent]): Result = {
  val userId = "user123"
  // ruleid: scala-cookie-usage
  Ok("User profile").withCookies(
    Cookie(name = "userId", value = userId)
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_3(request: Request[AnyContent]): Result = {
  val token = java.util.UUID.randomUUID().toString
  // ruleid: scala-cookie-usage
  Ok("Authentication complete").withCookies(
    Cookie("authToken", token, maxAge = Some(3600))
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_4(request: Request[AnyContent]): Result = {
  val preferences = "theme=dark;fontSize=large"
  // ruleid: scala-cookie-usage
  Ok("Preferences saved").withCookies(
    Cookie("userPrefs", preferences, path = Some("/account"))
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_5(request: Request[AnyContent]): Result = {
  // ruleid: scala-cookie-usage
  val cookie = Cookie("rememberMe", "true", maxAge = Some(86400 * 30))
  Ok("Remember me set").withCookies(cookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_6(request: Request[AnyContent]): Result = {
  val cartId = "cart_" + System.currentTimeMillis()
  // ruleid: scala-cookie-usage
  Ok("Cart created").withCookies(
    Cookie("cartId", cartId, maxAge = Some(3600), path = Some("/shop"))
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_7(request: Request[AnyContent]): Result = {
  // ruleid: scala-cookie-usage
  val cookie = Cookie(
    name = "lastVisit", 
    value = System.currentTimeMillis().toString, 
    domain = Some("example.com")
  )
  Ok("Welcome back").withCookies(cookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_8(): Result = {
  val sessionToken = "sess_" + java.util.UUID.randomUUID().toString
  // ruleid: scala-cookie-usage
  Ok("Session started").withCookies(
    Cookie("sessionToken", sessionToken, httpOnly = true) // Secure flag missing
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_9(): Result = {
  val authToken = "auth_" + java.util.UUID.randomUUID().toString
  // ruleid: scala-cookie-usage
  Ok("Authenticated").withCookies(
    Cookie("authToken", authToken, secure = true) // HttpOnly flag missing
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_10(request: Request[AnyContent]): Result = {
  val userId = request.getQueryString("userId").getOrElse("unknown")
  // ruleid: scala-cookie-usage
  Ok("User tracked").withCookies(
    Cookie("trackingId", userId + "_" + System.currentTimeMillis())
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_11(request: Request[AnyContent]): Result = {
  val language = request.getQueryString("lang").getOrElse("en")
  // ruleid: scala-cookie-usage
  val cookie = Cookie("language", language)
  Ok("Language preference set").withCookies(cookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_12(request: Request[AnyContent]): Result = {
  val marketingId = java.util.UUID.randomUUID().toString
  // ruleid: scala-cookie-usage
  val cookies = Seq(
    Cookie("marketingId", marketingId, maxAge = Some(86400 * 365)),
    Cookie("source", request.getQueryString("ref").getOrElse("direct"))
  )
  Ok("Marketing cookies set").withCookies(cookies: _*)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_13(request: Request[AnyContent]): Result = {
  // ruleid: scala-cookie-usage
  val result = Ok("Response with cookies")
    .withCookies(Cookie("visited", "true"))
    .withCookies(Cookie("timestamp", System.currentTimeMillis().toString))
  result
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_14(request: Request[AnyContent]): Result = {
  val cookieName = "sessionData"
  val cookieValue = "user=john;role=admin"
  // ruleid: scala-cookie-usage
  Ok("Session data stored").withCookies(
    Cookie(cookieName, cookieValue, path = Some("/"))
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_15(request: Request[AnyContent]): Result = {
  val cookieBuilder = Cookie.builder("analyticsId", java.util.UUID.randomUUID().toString)
    .withMaxAge(java.time.Duration.ofDays(30))
    .withPath("/")
  // ruleid: scala-cookie-usage
  Ok("Analytics cookie set").withCookies(cookieBuilder.build())
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

// True Negatives (Secure Code Examples)

def good_case_1(request: Request[AnyContent]): Result = {
  // ok: scala-cookie-usage
  Ok("Login successful").withCookies(
    Cookie("sessionId", "12345abcde", secure = true, httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_2(request: Request[AnyContent]): Result = {
  val userId = "user123"
  // ok: scala-cookie-usage
  Ok("User profile").withCookies(
    Cookie(name = "userId", value = userId, secure = true, httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_3(request: Request[AnyContent]): Result = {
  val token = java.util.UUID.randomUUID().toString
  // ok: scala-cookie-usage
  Ok("Authentication complete").withCookies(
    Cookie("authToken", token, maxAge = Some(3600), secure = true, httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_4(request: Request[AnyContent]): Result = {
  val preferences = "theme=dark;fontSize=large"
  // ok: scala-cookie-usage
  Ok("Preferences saved").withCookies(
    Cookie("userPrefs", preferences, path = Some("/account"), secure = true, httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_5(request: Request[AnyContent]): Result = {
  // ok: scala-cookie-usage
  val cookie = Cookie("rememberMe", "true", maxAge = Some(86400 * 30), secure = true, httpOnly = true)
  Ok("Remember me set").withCookies(cookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_6(request: Request[AnyContent]): Result = {
  val cartId = "cart_" + System.currentTimeMillis()
  // ok: scala-cookie-usage
  Ok("Cart created").withCookies(
    Cookie("cartId", cartId, maxAge = Some(3600), path = Some("/shop"), secure = true, httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_7(request: Request[AnyContent]): Result = {
  // ok: scala-cookie-usage
  val cookie = Cookie(
    name = "lastVisit", 
    value = System.currentTimeMillis().toString, 
    domain = Some("example.com"),
    secure = true,
    httpOnly = true
  )
  Ok("Welcome back").withCookies(cookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_8(): Result = {
  val sessionToken = "sess_" + java.util.UUID.randomUUID().toString
  // ok: scala-cookie-usage
  Ok("Session started").withCookies(
    Cookie("sessionToken", sessionToken, secure = true, httpOnly = true, sameSite = Some(Cookie.SameSite.Strict))
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_9(): Result = {
  val authToken = "auth_" + java.util.UUID.randomUUID().toString
  // ok: scala-cookie-usage
  Ok("Authenticated").withCookies(
    Cookie("authToken", authToken, secure = true, httpOnly = true, sameSite = Some(Cookie.SameSite.Lax))
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_10(request: Request[AnyContent]): Result = {
  val userId = request.getQueryString("userId").getOrElse("unknown")
  // ok: scala-cookie-usage
  Ok("User tracked").withCookies(
    Cookie("trackingId", userId + "_" + System.currentTimeMillis(), secure = true, httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_11(request: Request[AnyContent]): Result = {
  val language = request.getQueryString("lang").getOrElse("en")
  // ok: scala-cookie-usage
  val cookie = Cookie("language", language, secure = true, httpOnly = true)
  Ok("Language preference set").withCookies(cookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_12(request: Request[AnyContent]): Result = {
  val marketingId = java.util.UUID.randomUUID().toString
  // ok: scala-cookie-usage
  val cookies = Seq(
    Cookie("marketingId", marketingId, maxAge = Some(86400 * 365), secure = true, httpOnly = true),
    Cookie("source", request.getQueryString("ref").getOrElse("direct"), secure = true, httpOnly = true)
  )
  Ok("Marketing cookies set").withCookies(cookies: _*)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_13(request: Request[AnyContent]): Result = {
  // ok: scala-cookie-usage
  val result = Ok("Response with cookies")
    .withCookies(Cookie("visited", "true", secure = true, httpOnly = true))
    .withCookies(Cookie("timestamp", System.currentTimeMillis().toString, secure = true, httpOnly = true))
  result
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_14(request: Request[AnyContent]): Result = {
  val cookieName = "sessionData"
  val cookieValue = "user=john;role=admin"
  // ok: scala-cookie-usage
  Ok("Session data stored").withCookies(
    Cookie(cookieName, cookieValue, path = Some("/"), secure = true, httpOnly = true)
  )
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_15(request: Request[AnyContent]): Result = {
  val cookieBuilder = Cookie.builder("analyticsId", java.util.UUID.randomUUID().toString)
    .withMaxAge(java.time.Duration.ofDays(30))
    .withPath("/")
    .withSecure(true)
    .withHttpOnly(true)
  // ok: scala-cookie-usage
  Ok("Analytics cookie set").withCookies(cookieBuilder.build())
}
// {/fact}