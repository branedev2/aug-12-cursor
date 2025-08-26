import play.api.mvc._
import play.api.http.HeaderNames
import play.api.routing.Router
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import java.net.URL
import java.net.URI
import javax.inject.Inject
import play.api.libs.json.Json
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.HttpResponse
import akka.http.scaladsl.model.headers.Location
import akka.http.scaladsl.model.StatusCodes
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation._
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseEntity
import org.springframework.http.HttpStatus
import scala.util.matching.Regex
// {fact rule=cross-site-scripting@v1.0 defects=1}

// True Positives (Vulnerable Code)

// Case 1: Basic unvalidated redirect in Play Framework
def bad_case_1(request: Request[AnyContent]) = {
  val url = request.getQueryString("url").getOrElse("/default")
  // ruleid: scala-unvalidated-redirect
  Results.Redirect(url)
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Case 2: Unvalidated redirect with URL from POST body in Play Framework
def bad_case_2(request: Request[AnyContent]) = {
  val redirectUrl = request.body.asFormUrlEncoded.flatMap(_.get("redirectUrl").flatMap(_.headOption)).getOrElse("/home")
  // ruleid: scala-unvalidated-redirect
  Results.Redirect(redirectUrl, 302)
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Case 3: Unvalidated redirect with URL from header in Play Framework
def bad_case_3(request: Request[AnyContent]) = {
  val referer = request.headers.get(HeaderNames.REFERER).getOrElse("/")
  // ruleid: scala-unvalidated-redirect
  Results.Redirect(referer)
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Case 4: Unvalidated redirect with minimal string manipulation
def bad_case_4(request: Request[AnyContent]) = {
  val url = request.getQueryString("redirect").getOrElse("/home")
  val finalUrl = url.trim()
  // ruleid: scala-unvalidated-redirect
  Results.Redirect(finalUrl)
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Case 5: Unvalidated redirect with string concatenation
def bad_case_5(request: Request[AnyContent]) = {
  val path = request.getQueryString("path").getOrElse("")
  val redirectUrl = "/redirect/" + path
  // ruleid: scala-unvalidated-redirect
  Results.Redirect(redirectUrl)
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Case 6: Unvalidated redirect in Akka HTTP
def bad_case_6() = {
  path("redirect") {
    parameter("to") { url =>
      // ruleid: scala-unvalidated-redirect
      redirect(url, StatusCodes.Found)
    }
  }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Case 7: Unvalidated redirect with URL from JSON body in Play Framework
def bad_case_7(request: Request[AnyContent]) = {
  val redirectUrl = request.body.asJson.flatMap(json => (json \ "redirectUrl").asOpt[String]).getOrElse("/default")
  // ruleid: scala-unvalidated-redirect
  Results.Redirect(redirectUrl)
}
// {/fact}

// Case 8: Unvalidated redirect with Spring MVC
@Controller
class BadController8 {
  @GetMapping(Array("/redirect"))
  def bad_case_8(@RequestParam url: String): ResponseEntity[Void] = {
    val headers = new HttpHeaders()
    // ruleid: scala-unvalidated-redirect
    headers.add("Location", url)
    new ResponseEntity[Void](headers, HttpStatus.FOUND)
  }
}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Case 9: Unvalidated redirect with conditional logic
def bad_case_9(request: Request[AnyContent]) = {
  val url = request.getQueryString("url").getOrElse("/home")
  val finalUrl = if (url.startsWith("/")) url else "/" + url
  // ruleid: scala-unvalidated-redirect
  Results.Redirect(finalUrl)
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Case 10: Unvalidated redirect with URL from cookie
def bad_case_10(request: Request[AnyContent]) = {
  val redirectUrl = request.cookies.get("redirect_url").map(_.value).getOrElse("/default")
  // ruleid: scala-unvalidated-redirect
  Results.Redirect(redirectUrl)
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Case 11: Unvalidated redirect with URL encoded parameter
def bad_case_11(request: Request[AnyContent]) = {
  val encodedUrl = request.getQueryString("url").getOrElse("")
  val decodedUrl = java.net.URLDecoder.decode(encodedUrl, "UTF-8")
  // ruleid: scala-unvalidated-redirect
  Results.Redirect(decodedUrl)
}
// {/fact}

// Case 12: Unvalidated redirect with URL in path parameter
@Controller
class BadController12 {
  @GetMapping(Array("/go/{destination}"))
  def bad_case_12(@PathVariable destination: String): String = {
    // ruleid: scala-unvalidated-redirect
    s"redirect:$destination"
  }
}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Case 13: Unvalidated redirect with Akka HTTP and custom response
def bad_case_13() = {
  path("navigate") {
    parameter("to") { url =>
      // ruleid: scala-unvalidated-redirect
      complete(HttpResponse(
        status = StatusCodes.Found,
        headers = List(Location(Uri(url)))
      ))
    }
  }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Case 14: Unvalidated redirect with multiple parameters combined
def bad_case_14(request: Request[AnyContent]) = {
  val host = request.getQueryString("host").getOrElse("example.com")
  val path = request.getQueryString("path").getOrElse("/")
  val redirectUrl = s"https://$host$path"
  // ruleid: scala-unvalidated-redirect
  Results.Redirect(redirectUrl)
}
// {/fact}

// Case 15: Unvalidated redirect with Spring MVC and ResponseEntity builder
@Controller
class BadController15 {
  @GetMapping(Array("/external"))
  def bad_case_15(@RequestParam target: String): ResponseEntity[String] = {
    // ruleid: scala-unvalidated-redirect
    ResponseEntity.status(HttpStatus.FOUND)
      .header(HttpHeaders.LOCATION, target)
      .body("")
  }
}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// True Negatives (Safe Code)

// Case 1: Redirect to fixed URL in Play Framework
def good_case_1(request: Request[AnyContent]) = {
  // ok: scala-unvalidated-redirect
  Results.Redirect("/home")
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Case 2: Redirect with whitelist validation in Play Framework
def good_case_2(request: Request[AnyContent]) = {
  val url = request.getQueryString("url").getOrElse("/default")
  val allowedDomains = List("example.com", "trusted-site.org")
  
  try {
    val uri = new URI(url)
    val host = uri.getHost
    
    if (host == null || allowedDomains.exists(domain => host.endsWith(domain))) {
      // ok: scala-unvalidated-redirect
      Results.Redirect(url)
    } else {
      Results.Redirect("/default")
    }
  } catch {
    case _: Exception => Results.Redirect("/default")
  }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Case 3: Redirect with relative path validation in Play Framework
def good_case_3(request: Request[AnyContent]) = {
  val path = request.getQueryString("path").getOrElse("/home")
  
  if (path.startsWith("/") && !path.contains("://")) {
    // ok: scala-unvalidated-redirect
    Results.Redirect(path)
  } else {
    Results.Redirect("/home")
  }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Case 4: Redirect with strict whitelist in Play Framework
def good_case_4(request: Request[AnyContent]) = {
  val redirectId = request.getQueryString("id").getOrElse("home")
  
  val redirectMap = Map(
    "home" -> "/home",
    "login" -> "/auth/login",
    "dashboard" -> "/user/dashboard",
    "profile" -> "/user/profile"
  )
  
  // ok: scala-unvalidated-redirect
  Results.Redirect(redirectMap.getOrElse(redirectId, "/home"))
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Case 5: Redirect with regex validation in Play Framework
def good_case_5(request: Request[AnyContent]) = {
  val url = request.getQueryString("url").getOrElse("/home")
  val safeUrlPattern = "^/[a-zA-Z0-9/_-]*$".r
  
  safeUrlPattern.findFirstIn(url) match {
    case Some(safeUrl) => 
      // ok: scala-unvalidated-redirect
      Results.Redirect(safeUrl)
    case None => 
      Results.Redirect("/home")
  }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Case 6: Redirect with domain validation in Akka HTTP
def good_case_6() = {
  path("redirect") {
    parameter("to") { url =>
      val validDomains = Set("example.com", "trusted-site.org")
      
      try {
        val uri = new URI(url)
        val host = Option(uri.getHost)
        
        if (host.exists(h => validDomains.exists(h.endsWith))) {
          // ok: scala-unvalidated-redirect
          redirect(url, StatusCodes.Found)
        } else {
          redirect("/safe", StatusCodes.Found)
        }
      } catch {
        case _: Exception => redirect("/safe", StatusCodes.Found)
      }
    }
  }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Case 7: Redirect with path validation and sanitization
def good_case_7(request: Request[AnyContent]) = {
  val path = request.getQueryString("path").getOrElse("/")
  
  // Sanitize and validate the path
  val sanitizedPath = path.replaceAll("[^a-zA-Z0-9/_-]", "")
  val safePath = if (sanitizedPath.startsWith("/")) sanitizedPath else "/" + sanitizedPath
  
  // ok: scala-unvalidated-redirect
  Results.Redirect(safePath)
}
// {/fact}

// Case 8: Redirect with Spring MVC and whitelist validation
@Controller
class GoodController8 {
  @GetMapping(Array("/redirect"))
  def good_case_8(@RequestParam url: String): ResponseEntity[Void] = {
    val allowedUrls = List("/home", "/login", "/dashboard", "/profile")
    
    val headers = new HttpHeaders()
    if (allowedUrls.contains(url)) {
      // ok: scala-unvalidated-redirect
      headers.add("Location", url)
    } else {
      headers.add("Location", "/home")
    }
    
    new ResponseEntity[Void](headers, HttpStatus.FOUND)
  }
}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Case 9: Redirect with URL object validation
def good_case_9(request: Request[AnyContent]) = {
  val urlString = request.getQueryString("url").getOrElse("/default")
  
  try {
    val url = new URL(urlString)
    if (url.getHost == "trusted-domain.com" || url.getHost == "example.org") {
      // ok: scala-unvalidated-redirect
      Results.Redirect(urlString)
    } else {
      Results.Redirect("/default")
    }
  } catch {
    case _: Exception => Results.Redirect("/default")
  }
}
// {/fact}

// Case 10: Redirect with custom validation service
class UrlValidator {
  def isValid(url: String): Boolean = {
    val allowedDomains = List("example.com", "trusted-site.org")
    try {
      val uri = new URI(url)
      val host = uri.getHost
      host != null && allowedDomains.exists(domain => host.endsWith(domain))
    } catch {
      case _: Exception => false
    }
  }
}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_10(request: Request[AnyContent]) = {
  val url = request.getQueryString("url").getOrElse("/default")
  val validator = new UrlValidator()
  
  if (validator.isValid(url)) {
    // ok: scala-unvalidated-redirect
    Results.Redirect(url)
  } else {
    Results.Redirect("/default")
  }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Case 11: Redirect with relative path construction
def good_case_11(request: Request[AnyContent]) = {
  val section = request.getQueryString("section").getOrElse("home")
  val allowedSections = Set("home", "products", "about", "contact")
  
  val safePath = if (allowedSections.contains(section)) {
    s"/pages/$section"
  } else {
    "/pages/home"
  }
  
  // ok: scala-unvalidated-redirect
  Results.Redirect(safePath)
}
// {/fact}

// Case 12: Redirect with path parameter validation in Spring MVC
@Controller
class GoodController12 {
  @GetMapping(Array("/go/{destination}"))
  def good_case_12(@PathVariable destination: String): String = {
    val validDestinations = Set("home", "login", "profile", "settings")
    
    if (validDestinations.contains(destination)) {
      // ok: scala-unvalidated-redirect
      s"redirect:/$destination"
    } else {
      "redirect:/home"
    }
  }
}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Case 13: Redirect with Akka HTTP and custom validation
def good_case_13() = {
  path("navigate") {
    parameter("to") { url =>
      val safeUrlPattern: Regex = "^(https?://example\\.com/|/)[a-zA-Z0-9/_-]*$".r
      
      url match {
        case safeUrlPattern(_*) =>
          // ok: scala-unvalidated-redirect
          redirect(url, StatusCodes.Found)
        case _ =>
          redirect("/safe", StatusCodes.Found)
      }
    }
  }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Case 14: Redirect with domain and path validation
def good_case_14(request: Request[AnyContent]) = {
  val domain = request.getQueryString("domain").getOrElse("example.com")
  val path = request.getQueryString("path").getOrElse("/")
  
  val allowedDomains = Set("example.com", "trusted-site.org")
  val safePathPattern = "^/[a-zA-Z0-9/_-]*$".r
  
  if (allowedDomains.contains(domain) && safePathPattern.matches(path)) {
    // ok: scala-unvalidated-redirect
    Results.Redirect(s"https://$domain$path")
  } else {
    Results.Redirect("/default")
  }
}
// {/fact}

// Case 15: Redirect with Spring MVC and comprehensive validation
@Controller
class GoodController15 {
  @GetMapping(Array("/external"))
  def good_case_15(@RequestParam target: String): ResponseEntity[String] = {
    val allowedDomains = Set("example.com", "trusted-site.org")
    
    try {
      val uri = new URI(target)
      val host = Option(uri.getHost)
      val isRelative = host.isEmpty && !target.contains("://")
      val isSafeDomain = host.exists(h => allowedDomains.exists(h.endsWith))
      
      if (isRelative || isSafeDomain) {
        // ok: scala-unvalidated-redirect
        ResponseEntity.status(HttpStatus.FOUND)
          .header(HttpHeaders.LOCATION, target)
          .body("")
      } else {
        ResponseEntity.status(HttpStatus.FOUND)
          .header(HttpHeaders.LOCATION, "/default")
          .body("")
      }
    } catch {
      case _: Exception =>
        ResponseEntity.status(HttpStatus.FOUND)
          .header(HttpHeaders.LOCATION, "/default")
          .body("")
    }
  }
}