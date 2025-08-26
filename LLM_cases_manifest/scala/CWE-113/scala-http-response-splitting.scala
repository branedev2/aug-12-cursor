import scala.io.Source
import java.net.{HttpURLConnection, URL}
import play.api.mvc._
import play.api.http.HeaderNames
import play.api.http.{HttpEntity, Status}
import play.api.libs.json.Json
import akka.http.scaladsl.model.{HttpResponse, StatusCodes}
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import javax.servlet.http.{HttpServlet, HttpServletRequest, HttpServletResponse}
import org.springframework.web.bind.annotation._
import org.springframework.http.{HttpHeaders, ResponseEntity}
import org.springframework.stereotype.Controller
// {fact rule=http-response-splitting@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("redirect")
  
  // ruleid: scala-http-response-splitting
  response.setHeader("Location", userInput)
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_2(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userAgent = request.getHeader("User-Agent")
  
  // ruleid: scala-http-response-splitting
  response.addHeader("X-User-Agent", userAgent)
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_3(request: Request): Result = {
  val referer = request.headers.get("Referer").getOrElse("")
  
  // ruleid: scala-http-response-splitting
  Results.Ok("Response").withHeaders(
    "X-Referer" -> referer
  )
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_4(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val cookie = request.getParameter("cookieValue")
  
  // ruleid: scala-http-response-splitting
  response.addHeader("Set-Cookie", s"sessionId=${cookie}; Path=/; HttpOnly")
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_5(): Route = {
  path("redirect") {
    parameter("url") { url =>
      // ruleid: scala-http-response-splitting
      respondWithHeader("Location", url) {
        complete(StatusCodes.Found)
      }
    }
  }
}
// {/fact}

@Controller
def bad_case_6(): ResponseEntity[String] = {
  val request = org.springframework.web.context.request.RequestContextHolder.currentRequestAttributes()
    .asInstanceOf[org.springframework.web.context.request.ServletRequestAttributes]
    .getRequest()
  val customHeader = request.getParameter("header")
  
  val headers = new HttpHeaders()
  // ruleid: scala-http-response-splitting
  headers.add("X-Custom-Header", customHeader)
  
  new ResponseEntity[String]("Response", headers, org.springframework.http.HttpStatus.OK)
}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_7(request: Request): Result = {
  val language = request.getQueryString("lang").getOrElse("en")
  
  // ruleid: scala-http-response-splitting
  Results.Ok("Content").withHeaders(
    "Content-Language" -> language
  )
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_8(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val contentType = request.getParameter("type")
  
  // ruleid: scala-http-response-splitting
  response.setHeader("Content-Type", contentType)
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_9(): Route = {
  path("api") {
    get {
      extractRequest { request =>
        val origin = request.getHeader("Origin").getOrElse("")
        
        // ruleid: scala-http-response-splitting
        respondWithHeader("Access-Control-Allow-Origin", origin) {
          complete("API response")
        }
      }
    }
  }
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_10(request: Request): Result = {
  val redirectUrl = request.body.asFormUrlEncoded.get("url").head
  
  // ruleid: scala-http-response-splitting
  Results.Redirect(redirectUrl)
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_11(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("input")
  val headerValue = s"attachment; filename=${userInput}"
  
  // ruleid: scala-http-response-splitting
  response.setHeader("Content-Disposition", headerValue)
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_12(): Route = {
  path("download") {
    parameter("filename") { filename =>
      // ruleid: scala-http-response-splitting
      respondWithHeader("Content-Disposition", s"attachment; filename=${filename}") {
        complete("File content")
      }
    }
  }
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_13(request: Request): Result = {
  val cacheControl = request.getQueryString("cache").getOrElse("no-cache")
  
  // ruleid: scala-http-response-splitting
  Results.Ok("Content").withHeaders(
    "Cache-Control" -> cacheControl
  )
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_14(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val link = request.getParameter("link")
  
  // ruleid: scala-http-response-splitting
  response.addHeader("Link", s"<${link}>; rel=preload")
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=1}

def bad_case_15(request: Request): Result = {
  val customHeaderName = request.getQueryString("headerName").getOrElse("X-Custom")
  val customHeaderValue = request.getQueryString("headerValue").getOrElse("")
  
  // ruleid: scala-http-response-splitting
  Results.Ok("Response").withHeaders(
    customHeaderName -> customHeaderValue
  )
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

// True Negatives (Safe Code)

def good_case_1(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("redirect")
  val sanitizedInput = userInput.replaceAll("[\r\n]", "")
  
  // ok: scala-http-response-splitting
  response.setHeader("Location", sanitizedInput)
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_2(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userAgent = request.getHeader("User-Agent")
  val sanitizedUserAgent = userAgent.replaceAll("[\\r\\n]", "")
  
  // ok: scala-http-response-splitting
  response.addHeader("X-User-Agent", sanitizedUserAgent)
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_3(request: Request): Result = {
  val referer = request.headers.get("Referer").getOrElse("")
  val sanitizedReferer = referer.replaceAll("[\r\n]", "")
  
  // ok: scala-http-response-splitting
  Results.Ok("Response").withHeaders(
    "X-Referer" -> sanitizedReferer
  )
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_4(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val cookie = request.getParameter("cookieValue")
  val sanitizedCookie = cookie.replaceAll("[\\r\\n]", "")
  
  // ok: scala-http-response-splitting
  response.addHeader("Set-Cookie", s"sessionId=${sanitizedCookie}; Path=/; HttpOnly")
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_5(): Route = {
  path("redirect") {
    parameter("url") { url =>
      val sanitizedUrl = url.replaceAll("[\r\n]", "")
      
      // ok: scala-http-response-splitting
      respondWithHeader("Location", sanitizedUrl) {
        complete(StatusCodes.Found)
      }
    }
  }
}
// {/fact}

@Controller
def good_case_6(): ResponseEntity[String] = {
  val request = org.springframework.web.context.request.RequestContextHolder.currentRequestAttributes()
    .asInstanceOf[org.springframework.web.context.request.ServletRequestAttributes]
    .getRequest()
  val customHeader = request.getParameter("header")
  val sanitizedHeader = customHeader.replaceAll("[\\r\\n]", "")
  
  val headers = new HttpHeaders()
  // ok: scala-http-response-splitting
  headers.add("X-Custom-Header", sanitizedHeader)
  
  new ResponseEntity[String]("Response", headers, org.springframework.http.HttpStatus.OK)
}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_7(request: Request): Result = {
  val language = request.getQueryString("lang").getOrElse("en")
  val sanitizedLanguage = language.replaceAll("[\r\n]", "")
  
  // ok: scala-http-response-splitting
  Results.Ok("Content").withHeaders(
    "Content-Language" -> sanitizedLanguage
  )
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_8(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val contentType = request.getParameter("type")
  
  // Using a whitelist approach for content types
  val allowedTypes = Set("text/html", "application/json", "text/plain")
  val safeContentType = if (allowedTypes.contains(contentType)) contentType else "text/plain"
  
  // ok: scala-http-response-splitting
  response.setHeader("Content-Type", safeContentType)
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_9(): Route = {
  path("api") {
    get {
      extractRequest { request =>
        val origin = request.getHeader("Origin").getOrElse("")
        val sanitizedOrigin = origin.replaceAll("[\\r\\n]", "")
        
        // ok: scala-http-response-splitting
        respondWithHeader("Access-Control-Allow-Origin", sanitizedOrigin) {
          complete("API response")
        }
      }
    }
  }
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_10(request: Request): Result = {
  val redirectUrl = request.body.asFormUrlEncoded.get("url").head
  
  // Using a whitelist of allowed domains
  val allowedDomains = List("https://example.com", "https://trusted-site.com")
  val safeUrl = if (allowedDomains.exists(domain => redirectUrl.startsWith(domain))) {
    redirectUrl.replaceAll("[\\r\\n]", "")
  } else {
    "https://example.com/default"
  }
  
  // ok: scala-http-response-splitting
  Results.Redirect(safeUrl)
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_11(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("input")
  val sanitizedInput = userInput.replaceAll("[\\r\\n\"<>]", "")
  val headerValue = s"attachment; filename=${sanitizedInput}"
  
  // ok: scala-http-response-splitting
  response.setHeader("Content-Disposition", headerValue)
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_12(): Route = {
  path("download") {
    parameter("filename") { filename =>
      val sanitizedFilename = filename.replaceAll("[\\r\\n]", "")
      
      // ok: scala-http-response-splitting
      respondWithHeader("Content-Disposition", s"attachment; filename=${sanitizedFilename}") {
        complete("File content")
      }
    }
  }
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_13(request: Request): Result = {
  val cacheControl = request.getQueryString("cache").getOrElse("no-cache")
  
  // Using a whitelist approach for cache control values
  val allowedValues = Set("no-cache", "no-store", "must-revalidate", "public", "private")
  val safeCacheControl = if (allowedValues.contains(cacheControl)) cacheControl else "no-cache"
  
  // ok: scala-http-response-splitting
  Results.Ok("Content").withHeaders(
    "Cache-Control" -> safeCacheControl
  )
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_14(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val link = request.getParameter("link")
  val sanitizedLink = link.replaceAll("[\\r\\n<>\"']", "")
  
  // ok: scala-http-response-splitting
  response.addHeader("Link", s"<${sanitizedLink}>; rel=preload")
}
// {/fact}
// {fact rule=http-response-splitting@v1.0 defects=0}

def good_case_15(request: Request): Result = {
  // Using a hardcoded header instead of user input for the header name
  val customHeaderName = "X-Custom"
  val customHeaderValue = request.getQueryString("headerValue").getOrElse("")
  val sanitizedValue = customHeaderValue.replaceAll("[\r\n]", "")
  
  // ok: scala-http-response-splitting
  Results.Ok("Response").withHeaders(
    customHeaderName -> sanitizedValue
  )
}
// {/fact}