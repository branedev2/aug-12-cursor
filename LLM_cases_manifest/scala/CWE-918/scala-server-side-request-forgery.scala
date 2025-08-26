import scala.io.Source
import java.net.{URL, HttpURLConnection, URI}
import org.apache.http.client.methods.{HttpGet, HttpPost}
import org.apache.http.impl.client.{HttpClients, CloseableHttpClient}
import org.apache.http.client.config.RequestConfig
import org.apache.http.util.EntityUtils
import play.api.mvc._
import play.api.libs.ws._
import play.api.libs.json._
import akka.actor.ActorSystem
import akka.http.scaladsl.Http
import akka.http.scaladsl.model.{HttpRequest, HttpMethods}
import akka.stream.ActorMaterializer
import javax.inject.Inject
import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Try, Success, Failure}
import java.net.InetAddress
import scala.collection.immutable.Set
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(request: Request[AnyContent]): String = {
  // Using java.net.URL with user input directly
  val userUrl = request.getQueryString("url").getOrElse("https://default.com")
  // ruleid: scala-server-side-request-forgery
  val connection = new URL(userUrl).openConnection().asInstanceOf[HttpURLConnection]
  connection.setRequestMethod("GET")
  val response = Source.fromInputStream(connection.getInputStream).mkString
  connection.disconnect()
  response
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

def bad_case_2(request: Request[AnyContent]): String = {
  // Using Apache HttpClient with user input directly
  val userUrl = request.getQueryString("target").getOrElse("https://default.com")
  val httpClient = HttpClients.createDefault()
  // ruleid: scala-server-side-request-forgery
  val httpGet = new HttpGet(userUrl)
  val response = httpClient.execute(httpGet)
  val result = EntityUtils.toString(response.getEntity)
  httpClient.close()
  result
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

def bad_case_3(request: Request[AnyContent]): String = {
  // Using Scala Source with user input directly
  val userUrl = request.body.asFormUrlEncoded.flatMap(_.get("url").flatMap(_.headOption)).getOrElse("https://default.com")
  // ruleid: scala-server-side-request-forgery
  val result = Source.fromURL(userUrl).mkString
  result
}
// {/fact}

def bad_case_4(request: Request[AnyContent])(implicit ws: WSClient): Future[String] = {
  // Using Play WS client with user input directly
  val userUrl = request.headers.get("X-Target-Url").getOrElse("https://default.com")
  // ruleid: scala-server-side-request-forgery
  ws.url(userUrl).get().map { response =>
    response.body
  }(ExecutionContext.global)
}

def bad_case_5(request: Request[AnyContent]): Future[String] = {
  // Using Akka HTTP with user input directly
  implicit val system = ActorSystem()
  implicit val materializer = ActorMaterializer()
  implicit val executionContext = system.dispatcher
  
  val userUrl = request.getQueryString("api").getOrElse("https://default.com")
  // ruleid: scala-server-side-request-forgery
  Http().singleRequest(HttpRequest(uri = userUrl)).flatMap { response =>
    response.entity.toStrict(5000).map(_.data.utf8String)
  }
}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

def bad_case_6(request: Request[AnyContent]): String = {
  // Using java.net.URI with user input directly
  val userUrl = request.getQueryString("endpoint").getOrElse("https://default.com")
  val httpClient = HttpClients.createDefault()
  // ruleid: scala-server-side-request-forgery
  val httpGet = new HttpGet(new URI(userUrl))
  val response = httpClient.execute(httpGet)
  val result = EntityUtils.toString(response.getEntity)
  httpClient.close()
  result
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

def bad_case_7(request: Request[AnyContent]): String = {
  // Using string interpolation with user input
  val host = request.getQueryString("host").getOrElse("default.com")
  val path = request.getQueryString("path").getOrElse("/api")
  val url = s"https://$host$path"
  val httpClient = HttpClients.createDefault()
  // ruleid: scala-server-side-request-forgery
  val httpGet = new HttpGet(url)
  val response = httpClient.execute(httpGet)
  val result = EntityUtils.toString(response.getEntity)
  httpClient.close()
  result
}
// {/fact}

def bad_case_8(request: Request[AnyContent])(implicit ws: WSClient): Future[String] = {
  // Using Play WS client with concatenated user input
  val protocol = request.getQueryString("protocol").getOrElse("https")
  val domain = request.getQueryString("domain").getOrElse("default.com")
  val url = protocol + "://" + domain
  // ruleid: scala-server-side-request-forgery
  ws.url(url).get().map { response =>
    response.body
  }(ExecutionContext.global)
}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

def bad_case_9(request: Request[AnyContent]): String = {
  // Using JSON input for URL
  val jsonBody = request.body.asJson.getOrElse(Json.obj())
  val userUrl = (jsonBody \ "targetUrl").asOpt[String].getOrElse("https://default.com")
  // ruleid: scala-server-side-request-forgery
  val connection = new URL(userUrl).openConnection().asInstanceOf[HttpURLConnection]
  connection.setRequestMethod("GET")
  val response = Source.fromInputStream(connection.getInputStream).mkString
  connection.disconnect()
  response
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

def bad_case_10(request: Request[AnyContent]): String = {
  // Using POST data for URL with minimal processing
  val formData = request.body.asFormUrlEncoded.getOrElse(Map.empty)
  val userUrl = formData.getOrElse("url", Seq("https://default.com")).head
  val processedUrl = userUrl.trim
  // ruleid: scala-server-side-request-forgery
  val result = Source.fromURL(processedUrl).mkString
  result
}
// {/fact}

def bad_case_11(request: Request[AnyContent]): Future[String] = {
  // Using Akka HTTP with complex user input
  implicit val system = ActorSystem()
  implicit val materializer = ActorMaterializer()
  implicit val executionContext = system.dispatcher
  
  val baseUrl = request.getQueryString("baseUrl").getOrElse("https://default.com")
  val path = request.getQueryString("path").getOrElse("/api")
  val fullUrl = if (path.startsWith("/")) baseUrl + path else baseUrl + "/" + path
  // ruleid: scala-server-side-request-forgery
  Http().singleRequest(HttpRequest(uri = fullUrl)).flatMap { response =>
    response.entity.toStrict(5000).map(_.data.utf8String)
  }
}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

def bad_case_12(request: Request[AnyContent]): String = {
  // Using cookie value for URL
  val userUrl = request.cookies.get("target_url").map(_.value).getOrElse("https://default.com")
  val httpClient = HttpClients.createDefault()
  // ruleid: scala-server-side-request-forgery
  val httpGet = new HttpGet(userUrl)
  val response = httpClient.execute(httpGet)
  val result = EntityUtils.toString(response.getEntity)
  httpClient.close()
  result
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

def bad_case_13(request: Request[AnyContent]): String = {
  // Using referer header for URL
  val userUrl = request.headers.get("Referer").getOrElse("https://default.com")
  // ruleid: scala-server-side-request-forgery
  val connection = new URL(userUrl).openConnection().asInstanceOf[HttpURLConnection]
  connection.setRequestMethod("GET")
  val response = Source.fromInputStream(connection.getInputStream).mkString
  connection.disconnect()
  response
}
// {/fact}

def bad_case_14(request: Request[AnyContent])(implicit ws: WSClient): Future[String] = {
  // Using user-agent header for URL with conditional logic
  val userUrl = request.headers.get("User-Agent").getOrElse("https://default.com")
  val finalUrl = if (userUrl.contains("://")) userUrl else "https://" + userUrl
  // ruleid: scala-server-side-request-forgery
  ws.url(finalUrl).get().map { response =>
    response.body
  }(ExecutionContext.global)
}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

def bad_case_15(request: Request[AnyContent]): String = {
  // Using multiple parameters to construct URL
  val host = request.getQueryString("host").getOrElse("default.com")
  val port = request.getQueryString("port").getOrElse("443")
  val path = request.getQueryString("path").getOrElse("/")
  val protocol = request.getQueryString("protocol").getOrElse("https")
  
  val url = s"$protocol://$host:$port$path"
  val httpClient = HttpClients.createDefault()
  // ruleid: scala-server-side-request-forgery
  val httpGet = new HttpGet(url)
  val response = httpClient.execute(httpGet)
  val result = EntityUtils.toString(response.getEntity)
  httpClient.close()
  result
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// True Negative Examples (Safe Code)

def good_case_1(request: Request[AnyContent]): String = {
  // Using a whitelist of allowed domains
  val userUrl = request.getQueryString("url").getOrElse("https://default.com")
  val allowedDomains = Set("safe.com", "trusted.org", "default.com")
  
  val url = new URL(userUrl)
  val host = url.getHost
  
  // ok: scala-server-side-request-forgery
  if (allowedDomains.contains(host)) {
    val connection = url.openConnection().asInstanceOf[HttpURLConnection]
    connection.setRequestMethod("GET")
    val response = Source.fromInputStream(connection.getInputStream).mkString
    connection.disconnect()
    response
  } else {
    "Access denied: Domain not in whitelist"
  }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

def good_case_2(request: Request[AnyContent]): String = {
  // Using fixed URLs with path parameters
  val resourceId = request.getQueryString("id").getOrElse("default")
  val baseUrl = "https://api.trusted-service.com/resources/"
  
  // ok: scala-server-side-request-forgery
  val safeUrl = baseUrl + resourceId
  val httpClient = HttpClients.createDefault()
  val httpGet = new HttpGet(safeUrl)
  val response = httpClient.execute(httpGet)
  val result = EntityUtils.toString(response.getEntity)
  httpClient.close()
  result
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

def good_case_3(request: Request[AnyContent]): String = {
  // Using a URL builder with validation
  val path = request.getQueryString("path").getOrElse("/default")
  val baseUrl = new URL("https://api.trusted-service.com")
  
  // ok: scala-server-side-request-forgery
  val safeUrl = new URL(baseUrl, path)
  val connection = safeUrl.openConnection().asInstanceOf[HttpURLConnection]
  connection.setRequestMethod("GET")
  val response = Source.fromInputStream(connection.getInputStream).mkString
  connection.disconnect()
  response
}
// {/fact}

def good_case_4(request: Request[AnyContent])(implicit ws: WSClient): Future[String] = {
  // Using a service registry pattern
  val serviceId = request.getQueryString("service").getOrElse("default")
  val serviceRegistry = Map(
    "users" -> "https://users-api.internal.com",
    "products" -> "https://products-api.internal.com",
    "default" -> "https://default-api.internal.com"
  )
  
  // ok: scala-server-side-request-forgery
  val baseUrl = serviceRegistry.getOrElse(serviceId, serviceRegistry("default"))
  ws.url(baseUrl + "/api").get().map { response =>
    response.body
  }(ExecutionContext.global)
}

def good_case_5(request: Request[AnyContent]): Future[String] = {
  // Using Akka HTTP with fixed endpoints
  implicit val system = ActorSystem()
  implicit val materializer = ActorMaterializer()
  implicit val executionContext = system.dispatcher
  
  val endpoint = request.getQueryString("endpoint").getOrElse("users")
  val endpoints = Map(
    "users" -> "https://api.trusted-service.com/users",
    "products" -> "https://api.trusted-service.com/products"
  )
  
  // ok: scala-server-side-request-forgery
  val safeUrl = endpoints.getOrElse(endpoint, endpoints("users"))
  Http().singleRequest(HttpRequest(uri = safeUrl)).flatMap { response =>
    response.entity.toStrict(5000).map(_.data.utf8String)
  }
}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

def good_case_6(request: Request[AnyContent]): String = {
  // Using IP address validation
  val userIp = request.getQueryString("ip").getOrElse("192.168.1.1")
  
  try {
    val addr = InetAddress.getByName(userIp)
    // ok: scala-server-side-request-forgery
    if (!addr.isSiteLocalAddress && !addr.isLoopbackAddress && !addr.isLinkLocalAddress) {
      val httpClient = HttpClients.createDefault()
      val httpGet = new HttpGet("https://" + userIp)
      val response = httpClient.execute(httpGet)
      val result = EntityUtils.toString(response.getEntity)
      httpClient.close()
      result
    } else {
      "Access denied: Cannot access internal network"
    }
  } catch {
    case e: Exception => "Invalid IP address"
  }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

def good_case_7(request: Request[AnyContent]): String = {
  // Using a URL parser and protocol validation
  val userUrl = request.getQueryString("url").getOrElse("https://default.com")
  
  try {
    val url = new URL(userUrl)
    // ok: scala-server-side-request-forgery
    if (url.getProtocol == "https") {
      val connection = url.openConnection().asInstanceOf[HttpURLConnection]
      connection.setRequestMethod("GET")
      val response = Source.fromInputStream(connection.getInputStream).mkString
      connection.disconnect()
      response
    } else {
      "Access denied: Only HTTPS protocol is allowed"
    }
  } catch {
    case e: Exception => "Invalid URL"
  }
}
// {/fact}

def good_case_8(request: Request[AnyContent])(implicit ws: WSClient): Future[String] = {
  // Using port restriction
  val userUrl = request.getQueryString("url").getOrElse("https://default.com")
  
  try {
    val url = new URL(userUrl)
    val port = if (url.getPort == -1) url.getDefaultPort else url.getPort
    
    // ok: scala-server-side-request-forgery
    if (Set(80, 443).contains(port)) {
      ws.url(userUrl).get().map { response =>
        response.body
      }(ExecutionContext.global)
    } else {
      Future.successful("Access denied: Only standard HTTP/HTTPS ports allowed")
    }
  } catch {
    case e: Exception => Future.successful("Invalid URL")
  }
}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

def good_case_9(request: Request[AnyContent]): String = {
  // Using regex pattern matching for domain validation
  val userUrl = request.getQueryString("url").getOrElse("https://default.com")
  val domainPattern = "^https?://([a-zA-Z0-9-]+\\.)*trusted\\.com(/.*)?$".r
  
  // ok: scala-server-side-request-forgery
  domainPattern.findFirstMatchIn(userUrl) match {
    case Some(_) =>
      val httpClient = HttpClients.createDefault()
      val httpGet = new HttpGet(userUrl)
      val response = httpClient.execute(httpGet)
      val result = EntityUtils.toString(response.getEntity)
      httpClient.close()
      result
    case None =>
      "Access denied: URL must be from trusted.com domain"
  }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

def good_case_10(request: Request[AnyContent]): String = {
  // Using a predefined set of complete URLs
  val urlId = request.getQueryString("urlId").getOrElse("default")
  val allowedUrls = Map(
    "users" -> "https://api.trusted-service.com/users",
    "products" -> "https://api.trusted-service.com/products",
    "default" -> "https://api.trusted-service.com/home"
  )
  
  // ok: scala-server-side-request-forgery
  val safeUrl = allowedUrls.getOrElse(urlId, allowedUrls("default"))
  val connection = new URL(safeUrl).openConnection().asInstanceOf[HttpURLConnection]
  connection.setRequestMethod("GET")
  val response = Source.fromInputStream(connection.getInputStream).mkString
  connection.disconnect()
  response
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

def good_case_11(request: Request[AnyContent]): String = {
  // Using a proxy pattern with fixed target
  val path = request.getQueryString("path").getOrElse("/")
  val targetHost = "https://api.trusted-service.com"
  
  // ok: scala-server-side-request-forgery
  val safeUrl = targetHost + path
  val httpClient = HttpClients.createDefault()
  val httpGet = new HttpGet(safeUrl)
  val response = httpClient.execute(httpGet)
  val result = EntityUtils.toString(response.getEntity)
  httpClient.close()
  result
}
// {/fact}

def good_case_12(request: Request[AnyContent]): Future[String] = {
  // Using Akka HTTP with domain validation
  implicit val system = ActorSystem()
  implicit val materializer = ActorMaterializer()
  implicit val executionContext = system.dispatcher
  
  val userUrl = request.getQueryString("url").getOrElse("https://default.com")
  
  try {
    val url = new URL(userUrl)
    val host = url.getHost
    
    // ok: scala-server-side-request-forgery
    if (host.endsWith(".trusted.com") || host == "trusted.com") {
      Http().singleRequest(HttpRequest(uri = userUrl)).flatMap { response =>
        response.entity.toStrict(5000).map(_.data.utf8String)
      }
    } else {
      Future.successful("Access denied: Only trusted.com domains are allowed")
    }
  } catch {
    case e: Exception => Future.successful("Invalid URL")
  }
}

def good_case_13(request: Request[AnyContent])(implicit ws: WSClient): Future[String] = {
  // Using a URL builder with fixed base and validated path
  val path = request.getQueryString("path").getOrElse("/api")
  val sanitizedPath = path.replaceAll("[^a-zA-Z0-9/\\-_.]", "")
  val baseUrl = "https://api.trusted-service.com"
  
  // ok: scala-server-side-request-forgery
  val safeUrl = baseUrl + sanitizedPath
  ws.url(safeUrl).get().map { response =>
    response.body
  }(ExecutionContext.global)
}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

def good_case_14(request: Request[AnyContent]): String = {
  // Using a request config with timeout and redirects disabled
  val userUrl = request.getQueryString("url").getOrElse("https://default.com")
  val allowedDomains = Set("api.trusted.com", "data.trusted.com")
  
  try {
    val url = new URL(userUrl)
    val host = url.getHost
    
    // ok: scala-server-side-request-forgery
    if (allowedDomains.contains(host)) {
      val httpClient = HttpClients.custom()
        .setDefaultRequestConfig(
          RequestConfig.custom()
            .setConnectTimeout(5000)
            .setSocketTimeout(5000)
            .setRedirectsEnabled(false)
            .build()
        )
        .build()
      
      val httpGet = new HttpGet(userUrl)
      val response = httpClient.execute(httpGet)
      val result = EntityUtils.toString(response.getEntity)
      httpClient.close()
      result
    } else {
      "Access denied: Domain not allowed"
    }
  } catch {
    case e: Exception => "Invalid URL or connection error"
  }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

def good_case_15(request: Request[AnyContent]): String = {
  // Using resource identifiers instead of URLs
  val resourceId = request.getQueryString("id").getOrElse("default")
  val resourceType = request.getQueryString("type").getOrElse("users")
  
  val resourceMap = Map(
    "users" -> "https://api.internal.com/users/",
    "products" -> "https://api.internal.com/products/",
    "articles" -> "https://api.internal.com/articles/"
  )
  
  // ok: scala-server-side-request-forgery
  val baseUrl = resourceMap.getOrElse(resourceType, resourceMap("users"))
  val safeUrl = baseUrl + resourceId
  
  val httpClient = HttpClients.createDefault()
  val httpGet = new HttpGet(safeUrl)
  val response = httpClient.execute(httpGet)
  val result = EntityUtils.toString(response.getEntity)
  httpClient.close()
  result
}
// {/fact}