import play.api.mvc._
import play.api.http.HeaderNames
import play.api.libs.json.Json
import akka.http.scaladsl.model.HttpHeader
import akka.http.scaladsl.model.headers._
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import org.springframework.web.bind.annotation.{CrossOrigin, GetMapping, RestController}
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import scala.collection.immutable.Seq
// {fact rule=insecure-cors-policy@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(): Unit = {
  val result = Results.Ok("Response")
  // ruleid: scala-permissive-cors
  val response = result.withHeaders(
    "Access-Control-Allow-Origin" -> "*"
  )
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_2(): Unit = {
  val action = Action { request =>
    // ruleid: scala-permissive-cors
    Ok("Response").withHeaders(
      HeaderNames.ACCESS_CONTROL_ALLOW_ORIGIN -> "*",
      HeaderNames.ACCESS_CONTROL_ALLOW_METHODS -> "GET, POST, OPTIONS"
    )
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_3(): Unit = {
  val corsHeaders = Seq(
    // ruleid: scala-permissive-cors
    RawHeader("Access-Control-Allow-Origin", "*"),
    RawHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE"),
    RawHeader("Access-Control-Allow-Headers", "Content-Type, Authorization")
  )
  
  val route: Route = path("api") {
    respondWithHeaders(corsHeaders) {
      get {
        complete("API response")
      }
    }
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_4(): Unit = {
  def corsFilter(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    // ruleid: scala-permissive-cors
    response.setHeader("Access-Control-Allow-Origin", "*")
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization")
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_5(): Unit = {
  val route: Route = 
    cors() {
      path("data") {
        get {
          complete("Data response")
        }
      }
    }
  
  def cors(): Directive0 = {
    respondWithHeaders(
      // ruleid: scala-permissive-cors
      `Access-Control-Allow-Origin`.*,
      `Access-Control-Allow-Methods`(HttpMethods.GET, HttpMethods.POST),
      `Access-Control-Allow-Headers`("Content-Type")
    )
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_6(): Unit = {
  val origin = "*"
  // ruleid: scala-permissive-cors
  val response = Results.Ok("Response").withHeaders(
    "Access-Control-Allow-Origin" -> origin
  )
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_7(): Unit = {
  @RestController
  class ApiController {
    // ruleid: scala-permissive-cors
    @CrossOrigin(origins = Array("*"))
    @GetMapping(Array("/api/data"))
    def getData(): String = {
      "Data response"
    }
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_8(): Unit = {
  val userOrigin = "null" // Could be from user input
  
  // ruleid: scala-permissive-cors
  val response = Results.Ok("Response").withHeaders(
    "Access-Control-Allow-Origin" -> userOrigin
  )
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_9(): Unit = {
  def addCorsHeaders(response: HttpServletResponse): Unit = {
    // ruleid: scala-permissive-cors
    response.addHeader("Access-Control-Allow-Origin", "*")
    response.addHeader("Access-Control-Allow-Methods", "GET, POST")
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_10(): Unit = {
  val corsSettings = Map(
    // ruleid: scala-permissive-cors
    "Access-Control-Allow-Origin" -> "*",
    "Access-Control-Allow-Methods" -> "GET, POST, PUT, DELETE",
    "Access-Control-Allow-Headers" -> "Content-Type, Authorization"
  )
  
  val response = Results.Ok("Response").withHeaders(corsSettings.toSeq: _*)
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_11(): Unit = {
  val action = Action { request =>
    val origin = request.headers.get("Origin").getOrElse("*")
    
    // ruleid: scala-permissive-cors
    Ok("Response").withHeaders(
      HeaderNames.ACCESS_CONTROL_ALLOW_ORIGIN -> origin
    )
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_12(): Unit = {
  val wildcardDomain = "*.example.com"
  
  // ruleid: scala-permissive-cors
  val response = Results.Ok("Response").withHeaders(
    "Access-Control-Allow-Origin" -> wildcardDomain
  )
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_13(): Unit = {
  def configureCors(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val origin = request.getHeader("Origin")
    // Always accepting the origin without validation
    // ruleid: scala-permissive-cors
    response.setHeader("Access-Control-Allow-Origin", origin)
    response.setHeader("Access-Control-Allow-Credentials", "true")
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_14(): Unit = {
  val route: Route = 
    extractRequest { request =>
      val origin = request.headers.find(_.is("origin")).map(_.value()).getOrElse("*")
      
      respondWithHeaders(
        // ruleid: scala-permissive-cors
        RawHeader("Access-Control-Allow-Origin", origin),
        RawHeader("Access-Control-Allow-Methods", "GET, POST")
      ) {
        get {
          complete("Response")
        }
      }
    }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=1}

def bad_case_15(): Unit = {
  class CorsConfig {
    // ruleid: scala-permissive-cors
    val allowedOrigins = "*"
    val allowedMethods = "GET, POST, PUT, DELETE"
    
    def applyHeaders(response: HttpServletResponse): Unit = {
      response.setHeader("Access-Control-Allow-Origin", allowedOrigins)
      response.setHeader("Access-Control-Allow-Methods", allowedMethods)
    }
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

// True Negatives (Secure Code)

def good_case_1(): Unit = {
  val result = Results.Ok("Response")
  // ok: scala-permissive-cors
  val response = result.withHeaders(
    "Access-Control-Allow-Origin" -> "https://example.com"
  )
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_2(): Unit = {
  val allowedOrigins = Set("https://example.com", "https://api.example.com")
  
  val action = Action { request =>
    val origin = request.headers.get("Origin")
    val corsHeader = origin.filter(allowedOrigins.contains)
      .getOrElse("https://example.com")
    
    // ok: scala-permissive-cors
    Ok("Response").withHeaders(
      HeaderNames.ACCESS_CONTROL_ALLOW_ORIGIN -> corsHeader
    )
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_3(): Unit = {
  val allowedOrigin = "https://example.com"
  
  val corsHeaders = Seq(
    // ok: scala-permissive-cors
    RawHeader("Access-Control-Allow-Origin", allowedOrigin),
    RawHeader("Access-Control-Allow-Methods", "GET, POST")
  )
  
  val route: Route = path("api") {
    respondWithHeaders(corsHeaders) {
      get {
        complete("API response")
      }
    }
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_4(): Unit = {
  def corsFilter(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val allowedOrigins = Set("https://example.com", "https://api.example.com")
    val origin = request.getHeader("Origin")
    
    if (origin != null && allowedOrigins.contains(origin)) {
      // ok: scala-permissive-cors
      response.setHeader("Access-Control-Allow-Origin", origin)
    } else {
      response.setHeader("Access-Control-Allow-Origin", "https://example.com")
    }
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_5(): Unit = {
  val route: Route = 
    cors() {
      path("data") {
        get {
          complete("Data response")
        }
      }
    }
  
  def cors(): Directive0 = {
    // ok: scala-permissive-cors
    respondWithHeaders(
      `Access-Control-Allow-Origin`(HttpOrigin("https://example.com")),
      `Access-Control-Allow-Methods`(HttpMethods.GET, HttpMethods.POST)
    )
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_6(): Unit = {
  @RestController
  class ApiController {
    // ok: scala-permissive-cors
    @CrossOrigin(origins = Array("https://example.com", "https://api.example.com"))
    @GetMapping(Array("/api/data"))
    def getData(): String = {
      "Data response"
    }
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_7(): Unit = {
  val allowedOrigins = List("https://example.com", "https://api.example.com")
  
  val action = Action { request =>
    val origin = request.headers.get("Origin")
    val corsHeader = origin.filter(allowedOrigins.contains).getOrElse("https://example.com")
    
    // ok: scala-permissive-cors
    Ok("Response").withHeaders(
      HeaderNames.ACCESS_CONTROL_ALLOW_ORIGIN -> corsHeader,
      HeaderNames.ACCESS_CONTROL_ALLOW_METHODS -> "GET, POST"
    )
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_8(): Unit = {
  def validateAndSetCorsHeaders(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val allowedOrigins = Set("https://example.com", "https://api.example.com")
    val origin = request.getHeader("Origin")
    
    if (origin != null && allowedOrigins.contains(origin)) {
      // ok: scala-permissive-cors
      response.setHeader("Access-Control-Allow-Origin", origin)
      response.setHeader("Access-Control-Allow-Methods", "GET, POST")
    }
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_9(): Unit = {
  val corsSettings = Map(
    // ok: scala-permissive-cors
    "Access-Control-Allow-Origin" -> "https://example.com",
    "Access-Control-Allow-Methods" -> "GET, POST"
  )
  
  val response = Results.Ok("Response").withHeaders(corsSettings.toSeq: _*)
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_10(): Unit = {
  val route: Route = 
    extractRequest { request =>
      val allowedOrigins = Set("https://example.com", "https://api.example.com")
      val origin = request.headers.find(_.is("origin")).map(_.value())
      
      val corsHeader = origin.filter(allowedOrigins.contains).getOrElse("https://example.com")
      
      respondWithHeaders(
        // ok: scala-permissive-cors
        RawHeader("Access-Control-Allow-Origin", corsHeader)
      ) {
        get {
          complete("Response")
        }
      }
    }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_11(): Unit = {
  class CorsConfig {
    // ok: scala-permissive-cors
    val allowedOrigins = Set("https://example.com", "https://api.example.com")
    
    def applyHeaders(request: HttpServletRequest, response: HttpServletResponse): Unit = {
      val origin = request.getHeader("Origin")
      if (origin != null && allowedOrigins.contains(origin)) {
        response.setHeader("Access-Control-Allow-Origin", origin)
      }
    }
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_12(): Unit = {
  val action = Action { request =>
    val allowedOrigins = Set("https://example.com", "https://api.example.com")
    val origin = request.headers.get("Origin")
    
    // ok: scala-permissive-cors
    val headers = origin.filter(allowedOrigins.contains).map { o =>
      HeaderNames.ACCESS_CONTROL_ALLOW_ORIGIN -> o
    }.toSeq
    
    Ok("Response").withHeaders(headers: _*)
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_13(): Unit = {
  def configureCors(response: HttpServletResponse): Unit = {
    // ok: scala-permissive-cors
    response.setHeader("Access-Control-Allow-Origin", "https://example.com")
    response.setHeader("Access-Control-Allow-Methods", "GET, POST")
    response.setHeader("Access-Control-Max-Age", "3600")
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_14(): Unit = {
  val allowedOrigins = List("https://example.com", "https://api.example.com")
  
  def checkOrigin(origin: String): Boolean = {
    allowedOrigins.contains(origin)
  }
  
  val action = Action { request =>
    val origin = request.headers.get("Origin")
    
    // ok: scala-permissive-cors
    origin.filter(checkOrigin) match {
      case Some(validOrigin) => 
        Ok("Response").withHeaders(
          HeaderNames.ACCESS_CONTROL_ALLOW_ORIGIN -> validOrigin
        )
      case None =>
        Forbidden("Invalid origin")
    }
  }
}
// {/fact}
// {fact rule=insecure-cors-policy@v1.0 defects=0}

def good_case_15(): Unit = {
  val route: Route = 
    extractRequest { request =>
      val allowedOrigins = Set("https://example.com", "https://api.example.com")
      val origin = request.headers.find(_.is("origin")).map(_.value())
      
      // ok: scala-permissive-cors
      origin match {
        case Some(o) if allowedOrigins.contains(o) =>
          respondWithHeader(`Access-Control-Allow-Origin`(HttpOrigin(o))) {
            get {
              complete("Response")
            }
          }
        case _ =>
          complete(403, "Forbidden")
      }
    }
}
// {/fact}