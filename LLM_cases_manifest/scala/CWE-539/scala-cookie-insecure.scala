import javax.servlet.http.{HttpServlet, HttpServletRequest, HttpServletResponse, Cookie}
import play.api.mvc.{Action, Controller, Cookie => PlayCookie}
import play.api.http.{HeaderNames, HttpCookie}
import scala.collection.JavaConverters._
import akka.http.scaladsl.model.headers.{HttpCookie => AkkaHttpCookie}
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import org.apache.http.cookie.{Cookie => ApacheCookie}
import org.apache.http.impl.cookie.BasicClientCookie
// {fact rule=sensitive-information-leak@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(response: HttpServletResponse): Unit = {
  // Creating a sensitive cookie without the secure flag
  val authCookie = new Cookie("authToken", "abc123xyz789")
  authCookie.setMaxAge(3600)
  authCookie.setPath("/")
  // ruleid: scala-cookie-insecure
  response.addCookie(authCookie)
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_2(response: HttpServletResponse): Unit = {
  // Creating a session cookie without the secure flag
  val sessionCookie = new Cookie("JSESSIONID", "user123session456")
  sessionCookie.setHttpOnly(true) // Setting HttpOnly but not Secure
  // ruleid: scala-cookie-insecure
  response.addCookie(sessionCookie)
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_3(): PlayCookie = {
  // Play framework cookie without secure flag
  // ruleid: scala-cookie-insecure
  new PlayCookie(
    name = "userPreferences",
    value = "theme=dark;sidebar=true",
    maxAge = Some(86400),
    httpOnly = true
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_4(): PlayCookie = {
  // Play framework cookie with explicitly set secure=false
  // ruleid: scala-cookie-insecure
  PlayCookie(
    name = "rememberMe",
    value = "true",
    secure = false,
    httpOnly = true
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_5(): HttpCookie = {
  // Play HTTP cookie without secure flag
  // ruleid: scala-cookie-insecure
  HttpCookie(
    name = "sessionData",
    value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    maxAge = Some(3600)
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_6(): AkkaHttpCookie = {
  // Akka HTTP cookie without secure flag
  // ruleid: scala-cookie-insecure
  AkkaHttpCookie(
    name = "authToken",
    value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_7(): Route = {
  // Akka HTTP route setting cookie without secure flag
  path("login") {
    post {
      entity(as[String]) { _ =>
        // ruleid: scala-cookie-insecure
        setCookie(AkkaHttpCookie("sessionId", "abc123")) {
          complete("Login successful")
        }
      }
    }
  }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_8(response: HttpServletResponse): Unit = {
  // Multiple cookies, one without secure flag
  val cookie1 = new Cookie("analytics", "enabled")
  cookie1.setSecure(true)
  
  val cookie2 = new Cookie("sessionId", "user123456")
  // ruleid: scala-cookie-insecure
  response.addCookie(cookie1)
  response.addCookie(cookie2)
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_9(): BasicClientCookie = {
  // Apache HTTP client cookie without secure flag
  val cookie = new BasicClientCookie("apiToken", "secret-api-token-value")
  cookie.setDomain("example.com")
  cookie.setPath("/")
  // ruleid: scala-cookie-insecure
  cookie
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_10(response: HttpServletResponse): Unit = {
  // Conditional setting of cookie without secure flag
  val userCookie = new Cookie("userData", "preferences=dark")
  val isProduction = false
  
  if (isProduction) {
    userCookie.setSecure(true)
  }
  
  // ruleid: scala-cookie-insecure
  response.addCookie(userCookie)
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_11(): HttpCookie = {
  // Play HTTP cookie with explicitly set secure=false
  // ruleid: scala-cookie-insecure
  HttpCookie(
    name = "cart",
    value = "product1:2,product2:1",
    secure = false
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_12(response: HttpServletResponse): Unit = {
  // Creating a cookie with dynamic values but no secure flag
  val userId = "user_12345"
  val timestamp = System.currentTimeMillis().toString
  
  val trackingCookie = new Cookie("tracking", s"$userId:$timestamp")
  trackingCookie.setPath("/")
  trackingCookie.setMaxAge(2592000) // 30 days
  
  // ruleid: scala-cookie-insecure
  response.addCookie(trackingCookie)
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_13(): AkkaHttpCookie = {
  // Akka HTTP cookie with explicit secure=false
  // ruleid: scala-cookie-insecure
  AkkaHttpCookie(
    name = "userToken",
    value = "token123456",
    secure = false
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_14(): PlayCookie = {
  // Play framework cookie with missing secure flag and domain set
  // ruleid: scala-cookie-insecure
  PlayCookie(
    name = "preferences",
    value = "lang=en;theme=light",
    domain = Some("example.com"),
    path = Some("/account"),
    httpOnly = true
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

def bad_case_15(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  // Reading and modifying a cookie without setting secure flag
  val cookies = request.getCookies()
  if (cookies != null) {
    for (cookie <- cookies) {
      if (cookie.getName() == "sessionCounter") {
        val count = cookie.getValue().toInt + 1
        val updatedCookie = new Cookie("sessionCounter", count.toString)
        // ruleid: scala-cookie-insecure
        response.addCookie(updatedCookie)
      }
    }
  }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

// True Negative Examples (Secure Code)

def good_case_1(response: HttpServletResponse): Unit = {
  // Creating a cookie with the secure flag
  val authCookie = new Cookie("authToken", "abc123xyz789")
  authCookie.setMaxAge(3600)
  authCookie.setPath("/")
  // ok: scala-cookie-insecure
  authCookie.setSecure(true)
  response.addCookie(authCookie)
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_2(response: HttpServletResponse): Unit = {
  // Creating a session cookie with both secure and HttpOnly flags
  val sessionCookie = new Cookie("JSESSIONID", "user123session456")
  sessionCookie.setHttpOnly(true)
  // ok: scala-cookie-insecure
  sessionCookie.setSecure(true)
  response.addCookie(sessionCookie)
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_3(): PlayCookie = {
  // Play framework cookie with secure flag
  // ok: scala-cookie-insecure
  new PlayCookie(
    name = "userPreferences",
    value = "theme=dark;sidebar=true",
    maxAge = Some(86400),
    secure = true,
    httpOnly = true
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_4(): PlayCookie = {
  // Play framework cookie with explicitly set secure=true
  // ok: scala-cookie-insecure
  PlayCookie(
    name = "rememberMe",
    value = "true",
    secure = true,
    httpOnly = true
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_5(): HttpCookie = {
  // Play HTTP cookie with secure flag
  // ok: scala-cookie-insecure
  HttpCookie(
    name = "sessionData",
    value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    maxAge = Some(3600),
    secure = true
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_6(): AkkaHttpCookie = {
  // Akka HTTP cookie with secure flag
  // ok: scala-cookie-insecure
  AkkaHttpCookie(
    name = "authToken",
    value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
    secure = true
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_7(): Route = {
  // Akka HTTP route setting cookie with secure flag
  path("login") {
    post {
      entity(as[String]) { _ =>
        // ok: scala-cookie-insecure
        setCookie(AkkaHttpCookie("sessionId", "abc123", secure = true)) {
          complete("Login successful")
        }
      }
    }
  }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_8(response: HttpServletResponse): Unit = {
  // Multiple cookies, all with secure flag
  val cookie1 = new Cookie("analytics", "enabled")
  cookie1.setSecure(true)
  
  val cookie2 = new Cookie("sessionId", "user123456")
  // ok: scala-cookie-insecure
  cookie2.setSecure(true)
  response.addCookie(cookie1)
  response.addCookie(cookie2)
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_9(): BasicClientCookie = {
  // Apache HTTP client cookie with secure flag
  val cookie = new BasicClientCookie("apiToken", "secret-api-token-value")
  cookie.setDomain("example.com")
  cookie.setPath("/")
  // ok: scala-cookie-insecure
  cookie.setSecure(true)
  cookie
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_10(response: HttpServletResponse): Unit = {
  // Non-sensitive cookie that doesn't need secure flag
  val languageCookie = new Cookie("language", "en")
  languageCookie.setPath("/")
  // This is a non-sensitive cookie, so it's ok without secure flag
  // ok: scala-cookie-insecure
  response.addCookie(languageCookie)
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_11(): HttpCookie = {
  // Play HTTP cookie with secure flag set to true
  // ok: scala-cookie-insecure
  HttpCookie(
    name = "cart",
    value = "product1:2,product2:1",
    secure = true
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_12(response: HttpServletResponse): Unit = {
  // Creating a cookie with dynamic values and secure flag
  val userId = "user_12345"
  val timestamp = System.currentTimeMillis().toString
  
  val trackingCookie = new Cookie("tracking", s"$userId:$timestamp")
  trackingCookie.setPath("/")
  trackingCookie.setMaxAge(2592000) // 30 days
  // ok: scala-cookie-insecure
  trackingCookie.setSecure(true)
  response.addCookie(trackingCookie)
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_13(): AkkaHttpCookie = {
  // Akka HTTP cookie with explicit secure=true
  // ok: scala-cookie-insecure
  AkkaHttpCookie(
    name = "userToken",
    value = "token123456",
    secure = true,
    httpOnly = true
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_14(): PlayCookie = {
  // Play framework cookie with secure flag and domain set
  // ok: scala-cookie-insecure
  PlayCookie(
    name = "preferences",
    value = "lang=en;theme=light",
    domain = Some("example.com"),
    path = Some("/account"),
    secure = true,
    httpOnly = true
  )
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

def good_case_15(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  // Reading and modifying a cookie with secure flag
  val cookies = request.getCookies()
  if (cookies != null) {
    for (cookie <- cookies) {
      if (cookie.getName() == "sessionCounter") {
        val count = cookie.getValue().toInt + 1
        val updatedCookie = new Cookie("sessionCounter", count.toString)
        // ok: scala-cookie-insecure
        updatedCookie.setSecure(true)
        response.addCookie(updatedCookie)
      }
    }
  }
}
// {/fact}