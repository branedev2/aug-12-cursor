import play.api.mvc._
import play.api.http.HttpEntity
import play.api.libs.json._
import play.api.mvc.Results._
import play.api.routing.Router
import play.api.http.ContentTypes
import org.apache.commons.lang3.StringEscapeUtils
import org.owasp.encoder.Encode
import scala.concurrent.{ExecutionContext, Future}
import scala.xml.Unparsed
import scala.xml.XML
import javax.inject.Inject
import akka.util.ByteString
import play.twirl.api.Html

class XSSExamples @Inject() (implicit ec: ExecutionContext) extends Controller {

  // True Positive Examples (Vulnerable Code)

  def bad_case_1() = Action { request =>
    val userInput = request.getQueryString("name").getOrElse("")
    // ruleid: scala-cross-site-scripting
    Ok(s"<div>Hello, $userInput!</div>").as(ContentTypes.HTML)
  }

  def bad_case_2() = Action { request =>
    val userComment = request.body.asFormUrlEncoded.get("comment").head
    // ruleid: scala-cross-site-scripting
    Ok(s"""
      <html>
        <body>
          <h1>Your comment:</h1>
          <div>$userComment</div>
        </body>
      </html>
    """).as(ContentTypes.HTML)
  }

  def bad_case_3() = Action { request =>
    val searchTerm = request.getQueryString("q").getOrElse("")
    val results = s"Results for: $searchTerm"
    // ruleid: scala-cross-site-scripting
    Ok(views.html.search(Unparsed(results)))
  }

  def bad_case_4() = Action { request =>
    val username = request.headers.get("X-Username").getOrElse("")
    // ruleid: scala-cross-site-scripting
    Ok(Html(s"<div>Welcome back, $username</div>"))
  }

  def bad_case_5() = Action { request =>
    val script = request.getQueryString("customJs").getOrElse("")
    // ruleid: scala-cross-site-scripting
    Ok(s"""
      <html>
        <head>
          <script>
            $script
          </script>
        </head>
        <body>Custom JS loaded</body>
      </html>
    """).as(ContentTypes.HTML)
  }

  def bad_case_6() = Action { request =>
    val userId = request.getQueryString("id").getOrElse("")
    val htmlContent = s"<div id='user-$userId'>User profile</div>"
    // ruleid: scala-cross-site-scripting
    Ok(Html(htmlContent))
  }

  def bad_case_7() = Action { request =>
    val userInput = request.cookies.get("preference").map(_.value).getOrElse("")
    // ruleid: scala-cross-site-scripting
    val response = HttpEntity.Strict(
      ByteString(s"<div>Your preference: $userInput</div>"),
      Some(ContentTypes.HTML)
    )
    Result(ResponseHeader(200), response)
  }

  def bad_case_8() = Action { request =>
    val userProfile = Json.parse(request.body.asText.getOrElse("{}"))
    val name = (userProfile \ "name").asOpt[String].getOrElse("")
    // ruleid: scala-cross-site-scripting
    Ok(s"<div>Profile for: $name</div>").as(ContentTypes.HTML)
  }

  def bad_case_9() = Action { request =>
    val redirectUrl = request.getQueryString("redirect").getOrElse("/home")
    // ruleid: scala-cross-site-scripting
    Ok(s"""
      <html>
        <body>
          <a href="$redirectUrl">Click here to continue</a>
        </body>
      </html>
    """).as(ContentTypes.HTML)
  }

  def bad_case_10() = Action { request =>
    val style = request.getQueryString("theme").getOrElse("default")
    // ruleid: scala-cross-site-scripting
    Ok(s"""
      <html>
        <head>
          <style>
            body { background-color: $style; }
          </style>
        </head>
        <body>Theme applied</body>
      </html>
    """).as(ContentTypes.HTML)
  }

  def bad_case_11() = Action { request =>
    val title = request.getQueryString("title").getOrElse("Default Title")
    val content = request.getQueryString("content").getOrElse("")
    // ruleid: scala-cross-site-scripting
    Ok(s"""
      <html>
        <head><title>$title</title></head>
        <body>
          <h1>$title</h1>
          <div>$content</div>
        </body>
      </html>
    """).as(ContentTypes.HTML)
  }

  def bad_case_12() = Action.async { request =>
    val searchQuery = request.getQueryString("q").getOrElse("")
    // Simulate database search
    Future {
      val results = s"<ul><li>Result for: $searchQuery</li></ul>"
      // ruleid: scala-cross-site-scripting
      Ok(Html(results))
    }
  }

  def bad_case_13() = Action { request =>
    val xmlData = request.body.asText.getOrElse("<data></data>")
    val parsedXml = XML.loadString(xmlData)
    val username = (parsedXml \\ "username").text
    // ruleid: scala-cross-site-scripting
    Ok(s"<div>XML Username: $username</div>").as(ContentTypes.HTML)
  }

  def bad_case_14() = Action { request =>
    val userAgent = request.headers.get("User-Agent").getOrElse("")
    // ruleid: scala-cross-site-scripting
    Ok(s"""
      <html>
        <body>
          <div>You are using: $userAgent</div>
        </body>
      </html>
    """).as(ContentTypes.HTML)
  }

  def bad_case_15() = Action { request =>
    val lang = request.getQueryString("lang").getOrElse("en")
    val message = Map(
      "en" -> "Hello",
      "es" -> "Hola",
      "fr" -> "Bonjour"
    ).getOrElse(lang, lang) // If lang not in map, use the lang value itself
    
    // ruleid: scala-cross-site-scripting
    Ok(s"""
      <html>
        <body>
          <div data-lang="$lang">$message</div>
        </body>
      </html>
    """).as(ContentTypes.HTML)
  }

  // True Negative Examples (Safe Code)

  def good_case_1() = Action { request =>
    val userInput = request.getQueryString("name").getOrElse("")
    // ok: scala-cross-site-scripting
    val safeInput = StringEscapeUtils.escapeHtml4(userInput)
    Ok(s"<div>Hello, $safeInput!</div>").as(ContentTypes.HTML)
  }

  def good_case_2() = Action { request =>
    val userComment = request.body.asFormUrlEncoded.get("comment").head
    // ok: scala-cross-site-scripting
    val safeComment = Encode.forHtml(userComment)
    Ok(s"""
      <html>
        <body>
          <h1>Your comment:</h1>
          <div>$safeComment</div>
        </body>
      </html>
    """).as(ContentTypes.HTML)
  }

  def good_case_3() = Action { request =>
    val searchTerm = request.getQueryString("q").getOrElse("")
    // ok: scala-cross-site-scripting
    val safeSearchTerm = StringEscapeUtils.escapeHtml4(searchTerm)
    val results = s"Results for: $safeSearchTerm"
    Ok(views.html.search(Html(results)))
  }

  def good_case_4() = Action { request =>
    val username = request.headers.get("X-Username").getOrElse("")
    // ok: scala-cross-site-scripting
    val safeUsername = Encode.forHtml(username)
    Ok(Html(s"<div>Welcome back, $safeUsername</div>"))
  }

  def good_case_5() = Action { request =>
    val script = request.getQueryString("customJs").getOrElse("")
    // ok: scala-cross-site-scripting
    val safeScript = StringEscapeUtils.escapeEcmaScript(script)
    Ok(s"""
      <html>
        <head>
          <script>
            console.log("$safeScript");
          </script>
        </head>
        <body>Custom JS loaded</body>
      </html>
    """).as(ContentTypes.HTML)
  }

  def good_case_6() = Action { request =>
    val userId = request.getQueryString("id").getOrElse("")
    // ok: scala-cross-site-scripting
    val safeUserId = Encode.forHtmlAttribute(userId)
    val htmlContent = s"<div id='user-$safeUserId'>User profile</div>"
    Ok(Html(htmlContent))
  }

  def good_case_7() = Action { request =>
    val userInput = request.cookies.get("preference").map(_.value).getOrElse("")
    // ok: scala-cross-site-scripting
    val safeInput = StringEscapeUtils.escapeHtml4(userInput)
    val response = HttpEntity.Strict(
      ByteString(s"<div>Your preference: $safeInput</div>"),
      Some(ContentTypes.HTML)
    )
    Result(ResponseHeader(200), response)
  }

  def good_case_8() = Action { request =>
    val userProfile = Json.parse(request.body.asText.getOrElse("{}"))
    val name = (userProfile \ "name").asOpt[String].getOrElse("")
    // ok: scala-cross-site-scripting
    val safeName = Encode.forHtml(name)
    Ok(s"<div>Profile for: $safeName</div>").as(ContentTypes.HTML)
  }

  def good_case_9() = Action { request =>
    val redirectUrl = request.getQueryString("redirect").getOrElse("/home")
    // ok: scala-cross-site-scripting
    val safeUrl = Encode.forHtmlAttribute(redirectUrl)
    Ok(s"""
      <html>
        <body>
          <a href="$safeUrl">Click here to continue</a>
        </body>
      </html>
    """).as(ContentTypes.HTML)
  }

  def good_case_10() = Action { request =>
    val style = request.getQueryString("theme").getOrElse("default")
    // ok: scala-cross-site-scripting
    val safeStyle = Encode.forCssString(style)
    Ok(s"""
      <html>
        <head>
          <style>
            body { background-color: $safeStyle; }
          </style>
        </head>
        <body>Theme applied</body>
      </html>
    """).as(ContentTypes.HTML)
  }

  def good_case_11() = Action { request =>
    val title = request.getQueryString("title").getOrElse("Default Title")
    val content = request.getQueryString("content").getOrElse("")
    // ok: scala-cross-site-scripting
    val safeTitle = StringEscapeUtils.escapeHtml4(title)
    val safeContent = StringEscapeUtils.escapeHtml4(content)
    Ok(s"""
      <html>
        <head><title>$safeTitle</title></head>
        <body>
          <h1>$safeTitle</h1>
          <div>$safeContent</div>
        </body>
      </html>
    """).as(ContentTypes.HTML)
  }

  def good_case_12() = Action.async { request =>
    val searchQuery = request.getQueryString("q").getOrElse("")
    // Simulate database search
    Future {
      // ok: scala-cross-site-scripting
      val safeQuery = Encode.forHtml(searchQuery)
      val results = s"<ul><li>Result for: $safeQuery</li></ul>"
      Ok(Html(results))
    }
  }

  def good_case_13() = Action { request =>
    val xmlData = request.body.asText.getOrElse("<data></data>")
    val parsedXml = XML.loadString(xmlData)
    val username = (parsedXml \\ "username").text
    // ok: scala-cross-site-scripting
    val safeUsername = StringEscapeUtils.escapeHtml4(username)
    Ok(s"<div>XML Username: $safeUsername</div>").as(ContentTypes.HTML)
  }

  def good_case_14() = Action { request =>
    val userAgent = request.headers.get("User-Agent").getOrElse("")
    // ok: scala-cross-site-scripting
    val safeUserAgent = Encode.forHtml(userAgent)
    Ok(s"""
      <html>
        <body>
          <div>You are using: $safeUserAgent</div>
        </body>
      </html>
    """).as(ContentTypes.HTML)
  }

  def good_case_15() = Action { request =>
    val lang = request.getQueryString("lang").getOrElse("en")
    // ok: scala-cross-site-scripting
    val safeLang = Encode.forHtmlAttribute(lang)
    val message = Map(
      "en" -> "Hello",
      "es" -> "Hola",
      "fr" -> "Bonjour"
    ).getOrElse(lang, StringEscapeUtils.escapeHtml4(lang))
    
    Ok(s"""
      <html>
        <body>
          <div data-lang="$safeLang">$message</div>
        </body>
      </html>
    """).as(ContentTypes.HTML)
  }
}