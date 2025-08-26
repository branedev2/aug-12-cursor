// File: CSRFExamples.scala

import play.api.mvc._
import play.api.http.HeaderNames
import play.filters.csrf._
import play.api.libs.json._
import play.api.Configuration
import play.api.Environment
import play.api.http.HttpFilters
import javax.inject.Inject
import scala.concurrent.Future
import scala.concurrent.ExecutionContext
import akka.stream.Materializer
import play.api.routing.Router
import play.api.ApplicationLoader
import play.api.BuiltInComponentsFromContext
import play.api.NoHttpFiltersComponents
import play.api.mvc.Results._
import play.api.mvc.BodyParsers
import play.api.libs.ws.WSClient
import play.api.libs.ws.WSResponse

// True Positive Examples (Vulnerable Code)

class bad_case_1 @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  def processForm = Action { request =>
    // ruleid: scala-cross-site-request-forgery
    // Disabling CSRF check for all requests
    val csrfCheck = false
    if (csrfCheck) {
      // CSRF check would happen here, but it's disabled
    }
    Ok("Form processed without CSRF protection")
  }
}

class bad_case_2 extends CSRFFilter {
  override def apply(f: RequestHeader => Future[Result])(rh: RequestHeader): Future[Result] = {
    // ruleid: scala-cross-site-request-forgery
    // Bypassing CSRF check for all requests
    f(rh)
  }
}

class bad_case_3 @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  def processPayment = Action { request =>
    // ruleid: scala-cross-site-request-forgery
    // Explicitly skipping CSRF check for sensitive operation
    if (request.headers.get("X-Custom-Header").isDefined) {
      // Skip CSRF check if custom header is present
      Ok("Payment processed without CSRF verification")
    } else {
      Forbidden("CSRF token missing")
    }
  }
}

class bad_case_4 @Inject() (configuration: Configuration) {
  // ruleid: scala-cross-site-request-forgery
  // Disabling CSRF globally in configuration
  val csrfConfig = Map(
    "play.filters.csrf.enabled" -> false,
    "play.filters.enabled" -> Seq("play.filters.headers.SecurityHeadersFilter")
  )
  
  val config = Configuration.from(csrfConfig)
}

class bad_case_5 @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  def updateUserProfile = Action { request =>
    // ruleid: scala-cross-site-request-forgery
    // Accepting any content type including those that should be restricted
    val contentType = request.headers.get(HeaderNames.CONTENT_TYPE).getOrElse("")
    if (contentType.contains("application/json") || contentType.contains("text/plain")) {
      Ok("Profile updated")
    } else {
      BadRequest("Invalid content type")
    }
  }
}

class bad_case_6 extends CSRFFilter {
  // ruleid: scala-cross-site-request-forgery
  // Overriding shouldProtect to bypass CSRF for all JSON requests
  override def shouldProtect(request: RequestHeader): Boolean = {
    request.contentType.forall(_ != "application/json")
  }
}

class bad_case_7 @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  def deleteAccount = Action { request =>
    // ruleid: scala-cross-site-request-forgery
    // Bypassing CSRF check based on custom header that can be spoofed
    if (request.headers.get("X-Requested-With").contains("XMLHttpRequest")) {
      // Skip CSRF check for AJAX requests
      Ok("Account deleted")
    } else {
      Forbidden("CSRF token missing")
    }
  }
}

class bad_case_8 @Inject() (parser: BodyParsers.Default)(implicit ec: ExecutionContext) {
  // ruleid: scala-cross-site-request-forgery
  // Creating a custom body parser that skips CSRF checks
  val customParser = parser.tolerantJson.map { body =>
    // No CSRF validation happening here
    body
  }
}

class bad_case_9 extends CSRFFilter {
  // ruleid: scala-cross-site-request-forgery
  // Allowing all origins for CORS without proper CSRF protection
  override def filterHeaders(headers: Headers): Headers = {
    Headers(
      headers.toSimpleMap.toSeq :+ ("Access-Control-Allow-Origin" -> "*")
    )
  }
}

class bad_case_10 @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  def transferFunds = Action { request =>
    // ruleid: scala-cross-site-request-forgery
    // Bypassing CSRF check for requests with a specific referer
    val referer = request.headers.get(HeaderNames.REFERER)
    if (referer.exists(_.contains("trusted-domain.com"))) {
      // Process without CSRF check
      Ok("Funds transferred")
    } else {
      Forbidden("Invalid referer")
    }
  }
}

class bad_case_11 extends HttpFilters {
  // ruleid: scala-cross-site-request-forgery
  // Not including CSRF filter in the list of filters
  val filters: Seq[EssentialFilter] = Seq(
    new SecurityHeadersFilter()
    // CSRF filter is missing
  )
}

class bad_case_12 @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  def submitForm = Action { request =>
    // ruleid: scala-cross-site-request-forgery
    // Using an insecure token validation mechanism
    val token = request.headers.get("X-CSRF-Token").getOrElse("")
    if (token.length > 0) {
      // Any non-empty token is accepted
      Ok("Form submitted")
    } else {
      Forbidden("CSRF token missing")
    }
  }
}

class bad_case_13 @Inject() (cc: ControllerComponents, wsClient: WSClient) extends AbstractController(cc) {
  def proxyRequest = Action.async { request =>
    // ruleid: scala-cross-site-request-forgery
    // Forwarding requests without CSRF validation
    val url = request.getQueryString("url").getOrElse("https://default-api.com")
    wsClient.url(url).get().map { response =>
      Ok(response.body)
    }
  }
}

class bad_case_14 extends ApplicationLoader {
  // ruleid: scala-cross-site-request-forgery
  // Creating an application without CSRF components
  def load(context: ApplicationLoader.Context) = {
    new BuiltInComponentsFromContext(context) with NoHttpFiltersComponents {
      lazy val router = Router.empty
    }
  }.application
}

class bad_case_15 @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  def processApiRequest = Action { request =>
    // ruleid: scala-cross-site-request-forgery
    // Accepting all content types without restriction
    val contentType = request.headers.get(HeaderNames.CONTENT_TYPE)
    // No content type restrictions or CSRF checks
    Ok("API request processed")
  }
}

// True Negative Examples (Secure Code)

class good_case_1 @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  def processForm = Action { request =>
    // ok: scala-cross-site-request-forgery
    // Properly checking for CSRF token
    if (request.headers.get("Csrf-Token").contains("nocheck")) {
      Forbidden("CSRF check required")
    } else {
      // CSRF check passed (assuming the framework's built-in protection is enabled)
      Ok("Form processed with CSRF protection")
    }
  }
}

class good_case_2 @Inject() (addToken: CSRFAddToken, checkToken: CSRFCheck, cc: ControllerComponents) extends AbstractController(cc) {
  // ok: scala-cross-site-request-forgery
  // Using Play's built-in CSRF protection
  def submitForm = (checkToken andThen Action) { request =>
    Ok("Form submitted with CSRF protection")
  }
  
  def showForm = (addToken andThen Action) { request =>
    Ok(views.html.form(CSRF.getToken(request).get))
  }
}

class good_case_3 extends CSRFFilter {
  // ok: scala-cross-site-request-forgery
  // Properly implementing shouldProtect to protect all non-safe methods
  override def shouldProtect(request: RequestHeader): Boolean = {
    !request.method.toLowerCase.equals("get") && 
    !request.method.toLowerCase.equals("head") && 
    !request.method.toLowerCase.equals("options")
  }
}

class good_case_4 @Inject() (configuration: Configuration) {
  // ok: scala-cross-site-request-forgery
  // Enabling CSRF protection in configuration
  val csrfConfig = Map(
    "play.filters.csrf.enabled" -> true,
    "play.filters.enabled" -> Seq(
      "play.filters.csrf.CSRFFilter",
      "play.filters.headers.SecurityHeadersFilter"
    )
  )
  
  val config = Configuration.from(csrfConfig)
}

class good_case_5 @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  def updateUserProfile = Action { request =>
    // ok: scala-cross-site-request-forgery
    // Properly restricting content types for state-changing operations
    val contentType = request.headers.get(HeaderNames.CONTENT_TYPE).getOrElse("")
    val safeContentTypes = Seq("application/x-www-form-urlencoded", "multipart/form-data")
    
    if (safeContentTypes.exists(contentType.contains)) {
      Ok("Profile updated")
    } else {
      BadRequest("Invalid content type")
    }
  }
}

class good_case_6 extends CSRFFilter {
  // ok: scala-cross-site-request-forgery
  // Properly implementing token validation
  override def tokenProvider: TokenProvider = {
    new TokenProvider {
      def generateToken = CSRFTokenSigner.generateSignedToken
      def compareTokens(tokenA: String, tokenB: String) = CSRFTokenSigner.compareSignedTokens(tokenA, tokenB)
    }
  }
}

class good_case_7 @Inject() (addToken: CSRFAddToken, checkToken: CSRFCheck, cc: ControllerComponents) extends AbstractController(cc) {
  // ok: scala-cross-site-request-forgery
  // Using proper CSRF protection for sensitive operations
  def deleteAccount = (checkToken andThen Action) { request =>
    Ok("Account deleted with CSRF protection")
  }
}

class good_case_8 @Inject() (parser: BodyParsers.Default, checkToken: CSRFCheck)(implicit ec: ExecutionContext) {
  // ok: scala-cross-site-request-forgery
  // Creating a custom body parser that includes CSRF checks
  val customParser = checkToken(parser.tolerantJson)
}

class good_case_9 extends CSRFFilter {
  // ok: scala-cross-site-request-forgery
  // Properly configuring CORS with CSRF protection
  override def filterHeaders(headers: Headers): Headers = {
    val corsHeaders = Headers(
      "Access-Control-Allow-Origin" -> "https://trusted-domain.com",
      "Access-Control-Allow-Methods" -> "GET, POST",
      "Access-Control-Allow-Headers" -> "Origin, Content-Type, Accept, X-CSRF-Token"
    )
    Headers(headers.toSimpleMap.toSeq ++ corsHeaders.toSimpleMap.toSeq)
  }
}

class good_case_10 @Inject() (cc: ControllerComponents, checkToken: CSRFCheck) extends AbstractController(cc) {
  // ok: scala-cross-site-request-forgery
  // Using CSRF protection for fund transfers regardless of referer
  def transferFunds = (checkToken andThen Action) { request =>
    Ok("Funds transferred with CSRF protection")
  }
}

class good_case_11 @Inject() (csrfFilter: CSRFFilter) extends HttpFilters {
  // ok: scala-cross-site-request-forgery
  // Including CSRF filter in the list of filters
  val filters: Seq[EssentialFilter] = Seq(
    csrfFilter,
    new SecurityHeadersFilter()
  )
}

class good_case_12 @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  // ok: scala-cross-site-request-forgery
  // Using Play's built-in CSRF token validation
  def submitForm = Action { implicit request =>
    CSRF.getToken(request).map { token =>
      if (request.headers.get("Csrf-Token").contains(token.value)) {
        Ok("Form submitted with valid CSRF token")
      } else {
        Forbidden("Invalid CSRF token")
      }
    }.getOrElse(Forbidden("No CSRF token found"))
  }
}

class good_case_13 @Inject() (cc: ControllerComponents, wsClient: WSClient, checkToken: CSRFCheck) extends AbstractController(cc) {
  // ok: scala-cross-site-request-forgery
  // Validating CSRF token before proxying requests
  def proxyRequest = (checkToken andThen Action).async { request =>
    val url = "https://api.example.com/data"
    wsClient.url(url).get().map { response =>
      Ok(response.body)
    }
  }
}

class good_case_14 extends ApplicationLoader {
  // ok: scala-cross-site-request-forgery
  // Creating an application with CSRF components
  def load(context: ApplicationLoader.Context) = {
    new BuiltInComponentsFromContext(context) {
      lazy val router = Router.empty
      
      override lazy val httpFilters = Seq(
        csrfFilter,
        securityHeadersFilter
      )
      
      lazy val csrfFilter = new CSRFFilter()
      lazy val securityHeadersFilter = new SecurityHeadersFilter()
    }
  }.application
}

class good_case_15 @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  // ok: scala-cross-site-request-forgery
  // Restricting content types and using CSRF protection
  def processApiRequest = Action { request =>
    val contentType = request.headers.get(HeaderNames.CONTENT_TYPE).getOrElse("")
    val restrictedTypes = Seq("application/x-www-form-urlencoded", "multipart/form-data", "text/plain")
    
    if (restrictedTypes.exists(contentType.contains)) {
      // These content types require CSRF protection
      if (request.headers.get("Csrf-Token").isDefined) {
        Ok("API request processed with CSRF protection")
      } else {
        Forbidden("CSRF token required")
      }
    } else if (contentType.contains("application/json")) {
      // JSON requests with proper Origin/Host validation
      val origin = request.headers.get("Origin")
      val host = request.headers.get("Host")
      
      if (origin.isEmpty || host.isEmpty || origin.exists(_.contains(host.get))) {
        Ok("JSON API request processed")
      } else {
        Forbidden("Cross-origin request rejected")
      }
    } else {
      BadRequest("Unsupported content type")
    }
  }
}