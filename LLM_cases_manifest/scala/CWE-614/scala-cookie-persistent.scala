import javax.servlet.http.{Cookie, HttpServletRequest, HttpServletResponse}
import play.api.mvc._
import play.api.http.{HeaderNames, HttpVerbs}
import play.api.mvc.{Action, AnyContent, Cookie => PlayCookie}
import play.api.mvc.Results._
import play.api.mvc.ControllerComponents
import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.duration._
// {fact rule=insecure-cookie@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(response: HttpServletResponse): Unit = {
  val userCookie = new Cookie("authToken", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
  // ruleid: scala-cookie-persistent
  userCookie.setMaxAge(3600 * 24 * 30) // 30 days
  response.addCookie(userCookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_2(response: HttpServletResponse): Unit = {
  val sessionCookie = new Cookie("sessionId", "12345abcde67890")
  // ruleid: scala-cookie-persistent
  sessionCookie.setMaxAge(3600 * 24 * 365) // 1 year
  response.addCookie(sessionCookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_3(response: HttpServletResponse): Unit = {
  val userPrefs = new Cookie("userPreferences", "{\"theme\":\"dark\",\"token\":\"abc123def456\"}")
  // ruleid: scala-cookie-persistent
  userPrefs.setMaxAge(Integer.MAX_VALUE) // Maximum possible age
  response.addCookie(userPrefs)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_4(response: HttpServletResponse, userId: String): Unit = {
  val userIdCookie = new Cookie("userId", userId)
  // ruleid: scala-cookie-persistent
  userIdCookie.setMaxAge(3600 * 24 * 7) // 7 days
  userIdCookie.setSecure(true)
  userIdCookie.setHttpOnly(true)
  response.addCookie(userIdCookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_5(response: HttpServletResponse): Unit = {
  val creditCard = new Cookie("paymentInfo", "4111-1111-1111-1111")
  // ruleid: scala-cookie-persistent
  creditCard.setMaxAge(3600 * 3) // 3 hours
  response.addCookie(creditCard)
}
// {/fact}

class BadController(cc: ControllerComponents)(implicit ec: ExecutionContext) extends AbstractController(cc) {
  def bad_case_6(): Action[AnyContent] = Action { implicit request =>
    // ruleid: scala-cookie-persistent
    Ok("Login successful").withCookies(
      PlayCookie("authToken", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", maxAge = Some(3600 * 24 * 14))
    )
  }
}

class BadController2(cc: ControllerComponents)(implicit ec: ExecutionContext) extends AbstractController(cc) {
  def bad_case_7(): Action[AnyContent] = Action { implicit request =>
    // ruleid: scala-cookie-persistent
    Ok("User preferences saved").withCookies(
      PlayCookie("userKey", "sensitive-api-key-12345", maxAge = Some(3600 * 24 * 30), secure = true)
    )
  }
}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_8(response: HttpServletResponse): Unit = {
  val rememberMe = new Cookie("rememberMe", "true")
  val authToken = new Cookie("authToken", "sensitive-token-value")
  
  rememberMe.setMaxAge(3600 * 24 * 30) // 30 days - this is fine for a flag
  // ruleid: scala-cookie-persistent
  authToken.setMaxAge(3600 * 24 * 30) // 30 days - not fine for auth token
  
  response.addCookie(rememberMe)
  response.addCookie(authToken)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_9(response: HttpServletResponse): Unit = {
  val oneYear = 3600 * 24 * 365
  val sensitiveData = new Cookie("userData", "{\"ssn\":\"123-45-6789\",\"dob\":\"1990-01-01\"}")
  // ruleid: scala-cookie-persistent
  sensitiveData.setMaxAge(oneYear)
  response.addCookie(sensitiveData)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_10(response: HttpServletResponse, days: Int): Unit = {
  val maxAge = 3600 * 24 * days // Dynamic calculation
  val accessToken = new Cookie("accessToken", "oauth-token-xyz")
  // ruleid: scala-cookie-persistent
  accessToken.setMaxAge(maxAge) // Could be a long time
  response.addCookie(accessToken)
}
// {/fact}

class BadController3(cc: ControllerComponents)(implicit ec: ExecutionContext) extends AbstractController(cc) {
  def bad_case_11(): Action[AnyContent] = Action { implicit request =>
    val twoWeeks = 60 * 60 * 24 * 14
    // ruleid: scala-cookie-persistent
    Ok("Account created").withCookies(
      PlayCookie("accountId", "12345", maxAge = Some(twoWeeks))
    )
  }
}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_12(response: HttpServletResponse): Unit = {
  val loginCookie = new Cookie("loginCredentials", "username=admin&password=hash123")
  // ruleid: scala-cookie-persistent
  loginCookie.setMaxAge(3600 * 5) // 5 hours
  loginCookie.setSecure(true)
  loginCookie.setHttpOnly(true)
  response.addCookie(loginCookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_13(response: HttpServletResponse): Unit = {
  val apiKey = "api-key-12345"
  val apiCookie = new Cookie("apiAccess", apiKey)
  // ruleid: scala-cookie-persistent
  apiCookie.setMaxAge(3600 * 24) // 1 day
  response.addCookie(apiCookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_14(response: HttpServletResponse): Unit = {
  val twoWeeks = 3600 * 24 * 14
  val userToken = new Cookie("userToken", "sensitive-user-token")
  // ruleid: scala-cookie-persistent
  userToken.setMaxAge(twoWeeks)
  response.addCookie(userToken)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

def bad_case_15(response: HttpServletResponse): Unit = {
  val sensitiveInfo = new Cookie("personalInfo", "{\"address\":\"123 Main St\",\"phone\":\"555-1234\"}")
  // ruleid: scala-cookie-persistent
  sensitiveInfo.setMaxAge(3600 * 2) // Even 2 hours is too long for sensitive data
  response.addCookie(sensitiveInfo)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

// True Negatives (Secure Code)

def good_case_1(response: HttpServletResponse): Unit = {
  val userCookie = new Cookie("authToken", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
  // ok: scala-cookie-persistent
  userCookie.setMaxAge(-1) // Session cookie
  response.addCookie(userCookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_2(response: HttpServletResponse): Unit = {
  val sessionCookie = new Cookie("sessionId", "12345abcde67890")
  // ok: scala-cookie-persistent
  sessionCookie.setMaxAge(0) // Session cookie
  response.addCookie(sessionCookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_3(response: HttpServletResponse): Unit = {
  // Non-sensitive cookie can have longer expiration
  val themeCookie = new Cookie("theme", "dark")
  themeCookie.setMaxAge(3600 * 24 * 365) // 1 year is fine for non-sensitive data
  
  // Sensitive cookie has session-only expiration
  val authCookie = new Cookie("authToken", "sensitive-token")
  // ok: scala-cookie-persistent
  authCookie.setMaxAge(-1) // Session cookie
  
  response.addCookie(themeCookie)
  response.addCookie(authCookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_4(response: HttpServletResponse): Unit = {
  val userIdCookie = new Cookie("userId", "user123")
  // ok: scala-cookie-persistent
  // No setMaxAge call, defaults to session cookie
  userIdCookie.setSecure(true)
  userIdCookie.setHttpOnly(true)
  response.addCookie(userIdCookie)
}
// {/fact}

class GoodController(cc: ControllerComponents)(implicit ec: ExecutionContext) extends AbstractController(cc) {
  def good_case_5(): Action[AnyContent] = Action { implicit request =>
    // ok: scala-cookie-persistent
    Ok("Login successful").withCookies(
      PlayCookie("authToken", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", maxAge = None) // Session cookie
    )
  }
}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_6(response: HttpServletResponse): Unit = {
  // Using encryption for sensitive data in cookie
  import javax.crypto.Cipher
  import javax.crypto.spec.SecretKeySpec
  
  val key = new SecretKeySpec("secure-key-bytes".getBytes, "AES")
  val cipher = Cipher.getInstance("AES")
  cipher.init(Cipher.ENCRYPT_MODE, key)
  val encryptedData = cipher.doFinal("sensitive-data".getBytes)
  
  val secureCookie = new Cookie("encryptedData", new String(encryptedData))
  // ok: scala-cookie-persistent
  secureCookie.setMaxAge(300) // Short-lived (5 minutes)
  secureCookie.setSecure(true)
  secureCookie.setHttpOnly(true)
  response.addCookie(secureCookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_7(response: HttpServletResponse): Unit = {
  // Non-sensitive cookie can have longer expiration
  val preferenceCookie = new Cookie("language", "en-US")
  preferenceCookie.setMaxAge(3600 * 24 * 365) // 1 year
  
  // Sensitive cookie is session-only
  val sessionCookie = new Cookie("sessionId", "abc123")
  // ok: scala-cookie-persistent
  // No explicit setMaxAge, defaults to session cookie
  
  response.addCookie(preferenceCookie)
  response.addCookie(sessionCookie)
}
// {/fact}

class GoodController2(cc: ControllerComponents)(implicit ec: ExecutionContext) extends AbstractController(cc) {
  def good_case_8(): Action[AnyContent] = Action { implicit request =>
    // ok: scala-cookie-persistent
    Ok("User preferences saved").withCookies(
      PlayCookie("userKey", "sensitive-api-key-12345", maxAge = Some(300), secure = true) // 5 minutes
    )
  }
}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_9(response: HttpServletResponse): Unit = {
  val rememberMe = new Cookie("rememberMe", "true")
  val authToken = new Cookie("authToken", "sensitive-token-value")
  
  rememberMe.setMaxAge(3600 * 24 * 30) // 30 days - this is fine for a flag
  // ok: scala-cookie-persistent
  authToken.setMaxAge(-1) // Session cookie for auth token
  
  response.addCookie(rememberMe)
  response.addCookie(authToken)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_10(response: HttpServletResponse): Unit = {
  val accessToken = new Cookie("accessToken", "oauth-token-xyz")
  // ok: scala-cookie-persistent
  accessToken.setMaxAge(300) // 5 minutes
  accessToken.setSecure(true)
  accessToken.setHttpOnly(true)
  response.addCookie(accessToken)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_11(response: HttpServletResponse): Unit = {
  // Store only non-sensitive reference ID in cookie
  val referenceId = "ref-12345" // Reference to server-side stored sensitive data
  val refCookie = new Cookie("userRef", referenceId)
  // ok: scala-cookie-persistent
  refCookie.setMaxAge(3600) // 1 hour
  response.addCookie(refCookie)
  
  // Actual sensitive data is stored server-side
  // storeSessionData(referenceId, sensitiveData)
}
// {/fact}

class GoodController3(cc: ControllerComponents)(implicit ec: ExecutionContext) extends AbstractController(cc) {
  def good_case_12(): Action[AnyContent] = Action { implicit request =>
    // ok: scala-cookie-persistent
    Ok("Account created").withCookies(
      PlayCookie("accountId", "12345", maxAge = Some(60)) // Just 1 minute
    )
  }
}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_13(response: HttpServletResponse): Unit = {
  val loginCookie = new Cookie("loginCredentials", "username=admin&password=hash123")
  // ok: scala-cookie-persistent
  loginCookie.setMaxAge(60) // 1 minute
  loginCookie.setSecure(true)
  loginCookie.setHttpOnly(true)
  response.addCookie(loginCookie)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_14(response: HttpServletResponse): Unit = {
  // Non-sensitive data
  val analyticsCookie = new Cookie("analyticsId", "visitor-12345")
  analyticsCookie.setMaxAge(3600 * 24 * 365) // 1 year is fine for non-sensitive data
  
  // Sensitive data
  val userToken = new Cookie("userToken", "sensitive-user-token")
  // ok: scala-cookie-persistent
  userToken.setMaxAge(0) // Session cookie
  
  response.addCookie(analyticsCookie)
  response.addCookie(userToken)
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

def good_case_15(response: HttpServletResponse): Unit = {
  // Using JWT with short expiration for sensitive data
  val jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzk2MjJ9"
  val tokenCookie = new Cookie("jwtToken", jwtToken)
  // ok: scala-cookie-persistent
  tokenCookie.setMaxAge(600) // 10 minutes
  tokenCookie.setSecure(true)
  tokenCookie.setHttpOnly(true)
  response.addCookie(tokenCookie)
}
// {/fact}