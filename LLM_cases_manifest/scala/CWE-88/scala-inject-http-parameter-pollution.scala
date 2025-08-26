import scala.io.Source
import java.net.{URL, URLEncoder, HttpURLConnection}
import scala.util.Try
import org.http4s.UrlForm
import org.http4s.Uri
import org.apache.http.client.utils.URIBuilder
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClients
import play.api.mvc._
import play.api.http.HttpEntity
import akka.http.scaladsl.model.{HttpRequest, HttpMethods}
import akka.http.scaladsl.Http
import akka.actor.ActorSystem
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
// {fact rule=os-command-injection@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(request: Request[AnyContent]): String = {
  val userId = request.getQueryString("userId").getOrElse("")
  val apiUrl = s"https://api.example.com/users?id=${userId}&format=json"
  // ruleid: scala-inject-http-parameter-pollution
  val response = Source.fromURL(apiUrl).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_2(request: Request[AnyContent]): String = {
  val searchTerm = request.getQueryString("q").getOrElse("")
  val sortOrder = request.getQueryString("sort").getOrElse("asc")
  // ruleid: scala-inject-http-parameter-pollution
  val apiUrl = s"https://api.example.com/search?query=${searchTerm}&sort=${sortOrder}"
  val connection = new URL(apiUrl).openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_3(request: Request[AnyContent]): String = {
  val category = request.getQueryString("category").getOrElse("all")
  val page = request.getQueryString("page").getOrElse("1")
  // ruleid: scala-inject-http-parameter-pollution
  val url = new URL(s"https://api.example.com/products?category=${category}&page=${page}")
  val connection = url.openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_4(request: Request[AnyContent]): String = {
  val username = request.body.asFormUrlEncoded.flatMap(_.get("username").map(_.head)).getOrElse("")
  val token = request.cookies.get("auth_token").map(_.value).getOrElse("")
  // ruleid: scala-inject-http-parameter-pollution
  val apiUrl = s"https://api.example.com/validate?user=${username}&token=${token}"
  val response = Source.fromURL(apiUrl).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_5(request: Request[AnyContent]): String = {
  val filters = request.queryString.map { case (key, values) => 
    s"$key=${values.mkString(",")}"
  }.mkString("&")
  // ruleid: scala-inject-http-parameter-pollution
  val apiUrl = s"https://api.example.com/search?${filters}"
  val connection = new URL(apiUrl).openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_6(request: Request[AnyContent]): String = {
  val productId = request.getQueryString("productId").getOrElse("")
  val userId = request.session.get("userId").getOrElse("")
  // ruleid: scala-inject-http-parameter-pollution
  val apiUrl = s"https://api.example.com/recommendations?productId=${productId}&userId=${userId}"
  val response = Source.fromURL(apiUrl).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_7(request: Request[AnyContent]): String = {
  val latitude = request.getQueryString("lat").getOrElse("0")
  val longitude = request.getQueryString("lng").getOrElse("0")
  val radius = request.getQueryString("radius").getOrElse("10")
  // ruleid: scala-inject-http-parameter-pollution
  val apiUrl = s"https://maps.example.com/nearby?lat=${latitude}&lng=${longitude}&radius=${radius}"
  val connection = new URL(apiUrl).openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_8(request: Request[AnyContent]): String = {
  val email = request.body.asFormUrlEncoded.flatMap(_.get("email").map(_.head)).getOrElse("")
  // ruleid: scala-inject-http-parameter-pollution
  val apiUrl = s"https://api.example.com/subscribe?email=${email}&source=website"
  val response = Source.fromURL(apiUrl).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_9(request: Request[AnyContent]): String = {
  val referer = request.headers.get("Referer").getOrElse("")
  val userAgent = request.headers.get("User-Agent").getOrElse("")
  // ruleid: scala-inject-http-parameter-pollution
  val apiUrl = s"https://analytics.example.com/track?referer=${referer}&userAgent=${userAgent}"
  val connection = new URL(apiUrl).openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_10(request: Request[AnyContent]): String = {
  implicit val system = ActorSystem()
  val query = request.getQueryString("q").getOrElse("")
  // ruleid: scala-inject-http-parameter-pollution
  val uri = s"https://api.example.com/search?q=${query}"
  val httpRequest = HttpRequest(HttpMethods.GET, uri)
  val responseFuture = Http().singleRequest(httpRequest)
  "Request sent"
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_11(request: Request[AnyContent]): String = {
  val sessionId = request.cookies.get("sessionId").map(_.value).getOrElse("")
  val action = request.getQueryString("action").getOrElse("view")
  // ruleid: scala-inject-http-parameter-pollution
  val apiUrl = s"https://api.example.com/session?id=${sessionId}&action=${action}"
  val response = Source.fromURL(apiUrl).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_12(request: Request[AnyContent]): String = {
  val client = HttpClients.createDefault()
  val searchTerm = request.getQueryString("search").getOrElse("")
  // ruleid: scala-inject-http-parameter-pollution
  val httpGet = new HttpGet(s"https://api.example.com/search?q=${searchTerm}")
  val response = client.execute(httpGet)
  response.toString
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_13(request: Request[AnyContent]): String = {
  val tags = request.queryString.getOrElse("tags", Seq()).mkString(",")
  // ruleid: scala-inject-http-parameter-pollution
  val apiUrl = s"https://api.example.com/filter?tags=${tags}"
  val connection = new URL(apiUrl).openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_14(request: Request[AnyContent]): String = {
  val language = request.headers.get("Accept-Language").getOrElse("en")
  val country = request.getQueryString("country").getOrElse("US")
  // ruleid: scala-inject-http-parameter-pollution
  val apiUrl = s"https://api.example.com/localize?lang=${language}&country=${country}"
  val response = Source.fromURL(apiUrl).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

def bad_case_15(request: Request[AnyContent]): String = {
  val callback = request.getQueryString("callback").getOrElse("defaultCallback")
  val data = request.body.asJson.map(_.toString()).getOrElse("{}")
  // ruleid: scala-inject-http-parameter-pollution
  val apiUrl = s"https://api.example.com/jsonp?callback=${callback}&data=${data}"
  val connection = new URL(apiUrl).openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

// True Negatives (Safe Code)

def good_case_1(request: Request[AnyContent]): String = {
  val userId = request.getQueryString("userId").getOrElse("")
  // ok: scala-inject-http-parameter-pollution
  val apiUrl = s"https://api.example.com/users?id=${URLEncoder.encode(userId, "UTF-8")}&format=json"
  val response = Source.fromURL(apiUrl).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_2(request: Request[AnyContent]): String = {
  val searchTerm = request.getQueryString("q").getOrElse("")
  val sortOrder = request.getQueryString("sort").getOrElse("asc")
  val builder = new URIBuilder("https://api.example.com/search")
  // ok: scala-inject-http-parameter-pollution
  builder.addParameter("query", searchTerm)
  builder.addParameter("sort", sortOrder)
  val uri = builder.build()
  val client = HttpClients.createDefault()
  val httpGet = new HttpGet(uri)
  val response = client.execute(httpGet)
  response.toString
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_3(request: Request[AnyContent]): String = {
  val category = request.getQueryString("category").getOrElse("all")
  val page = request.getQueryString("page").getOrElse("1")
  // ok: scala-inject-http-parameter-pollution
  val encodedCategory = URLEncoder.encode(category, "UTF-8")
  val encodedPage = URLEncoder.encode(page, "UTF-8")
  val url = new URL(s"https://api.example.com/products?category=${encodedCategory}&page=${encodedPage}")
  val connection = url.openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_4(request: Request[AnyContent]): String = {
  val username = request.body.asFormUrlEncoded.flatMap(_.get("username").map(_.head)).getOrElse("")
  val token = request.cookies.get("auth_token").map(_.value).getOrElse("")
  // ok: scala-inject-http-parameter-pollution
  val params = UrlForm(
    "user" -> username,
    "token" -> token
  )
  val uri = Uri.unsafeFromString("https://api.example.com/validate").withQueryParams(params)
  uri.toString
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_5(request: Request[AnyContent]): String = {
  val builder = new URIBuilder("https://api.example.com/search")
  // ok: scala-inject-http-parameter-pollution
  request.queryString.foreach { case (key, values) =>
    values.foreach(value => builder.addParameter(key, value))
  }
  val uri = builder.build()
  val client = HttpClients.createDefault()
  val httpGet = new HttpGet(uri)
  val response = client.execute(httpGet)
  response.toString
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_6(request: Request[AnyContent]): String = {
  val productId = request.getQueryString("productId").getOrElse("")
  val userId = request.session.get("userId").getOrElse("")
  val builder = new URIBuilder("https://api.example.com/recommendations")
  // ok: scala-inject-http-parameter-pollution
  builder.addParameter("productId", productId)
  builder.addParameter("userId", userId)
  val uri = builder.build()
  val client = HttpClients.createDefault()
  val httpGet = new HttpGet(uri)
  val response = client.execute(httpGet)
  response.toString
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_7(request: Request[AnyContent]): String = {
  val latitude = request.getQueryString("lat").getOrElse("0")
  val longitude = request.getQueryString("lng").getOrElse("0")
  val radius = request.getQueryString("radius").getOrElse("10")
  // ok: scala-inject-http-parameter-pollution
  val encodedLat = URLEncoder.encode(latitude, "UTF-8")
  val encodedLng = URLEncoder.encode(longitude, "UTF-8")
  val encodedRadius = URLEncoder.encode(radius, "UTF-8")
  val apiUrl = s"https://maps.example.com/nearby?lat=${encodedLat}&lng=${encodedLng}&radius=${encodedRadius}"
  val connection = new URL(apiUrl).openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_8(request: Request[AnyContent]): String = {
  val email = request.body.asFormUrlEncoded.flatMap(_.get("email").map(_.head)).getOrElse("")
  val builder = new URIBuilder("https://api.example.com/subscribe")
  // ok: scala-inject-http-parameter-pollution
  builder.addParameter("email", email)
  builder.addParameter("source", "website")
  val uri = builder.build()
  val client = HttpClients.createDefault()
  val httpGet = new HttpGet(uri)
  val response = client.execute(httpGet)
  response.toString
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_9(request: Request[AnyContent]): String = {
  val referer = request.headers.get("Referer").getOrElse("")
  val userAgent = request.headers.get("User-Agent").getOrElse("")
  // ok: scala-inject-http-parameter-pollution
  val params = Map(
    "referer" -> referer,
    "userAgent" -> userAgent
  ).map { case (k, v) => s"${k}=${URLEncoder.encode(v, "UTF-8")}" }.mkString("&")
  val apiUrl = s"https://analytics.example.com/track?${params}"
  val connection = new URL(apiUrl).openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  response
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_10(request: Request[AnyContent]): String = {
  implicit val system = ActorSystem()
  val query = request.getQueryString("q").getOrElse("")
  // ok: scala-inject-http-parameter-pollution
  val encodedQuery = URLEncoder.encode(query, "UTF-8")
  val uri = s"https://api.example.com/search?q=${encodedQuery}"
  val httpRequest = HttpRequest(HttpMethods.GET, uri)
  val responseFuture = Http().singleRequest(httpRequest)
  "Request sent"
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_11(request: Request[AnyContent]): String = {
  val sessionId = request.cookies.get("sessionId").map(_.value).getOrElse("")
  val action = request.getQueryString("action").getOrElse("view")
  val builder = new URIBuilder("https://api.example.com/session")
  // ok: scala-inject-http-parameter-pollution
  builder.addParameter("id", sessionId)
  builder.addParameter("action", action)
  val uri = builder.build()
  val client = HttpClients.createDefault()
  val httpGet = new HttpGet(uri)
  val response = client.execute(httpGet)
  response.toString
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_12(request: Request[AnyContent]): String = {
  val client = HttpClients.createDefault()
  val searchTerm = request.getQueryString("search").getOrElse("")
  val builder = new URIBuilder("https://api.example.com/search")
  // ok: scala-inject-http-parameter-pollution
  builder.addParameter("q", searchTerm)
  val uri = builder.build()
  val httpGet = new HttpGet(uri)
  val response = client.execute(httpGet)
  response.toString
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_13(request: Request[AnyContent]): String = {
  val tags = request.queryString.getOrElse("tags", Seq())
  val builder = new URIBuilder("https://api.example.com/filter")
  // ok: scala-inject-http-parameter-pollution
  tags.foreach(tag => builder.addParameter("tags", tag))
  val uri = builder.build()
  val client = HttpClients.createDefault()
  val httpGet = new HttpGet(uri)
  val response = client.execute(httpGet)
  response.toString
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_14(request: Request[AnyContent]): String = {
  val language = request.headers.get("Accept-Language").getOrElse("en")
  val country = request.getQueryString("country").getOrElse("US")
  // ok: scala-inject-http-parameter-pollution
  val params = UrlForm(
    "lang" -> language,
    "country" -> country
  )
  val uri = Uri.unsafeFromString("https://api.example.com/localize").withQueryParams(params)
  uri.toString
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

def good_case_15(request: Request[AnyContent]): String = {
  val callback = request.getQueryString("callback").getOrElse("defaultCallback")
  val data = request.body.asJson.map(_.toString()).getOrElse("{}")
  // ok: scala-inject-http-parameter-pollution
  val encodedCallback = URLEncoder.encode(callback, "UTF-8")
  val encodedData = URLEncoder.encode(data, "UTF-8")
  val apiUrl = s"https://api.example.com/jsonp?callback=${encodedCallback}&data=${encodedData}"
  val connection = new URL(apiUrl).openConnection().asInstanceOf[HttpURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  response
}
// {/fact}