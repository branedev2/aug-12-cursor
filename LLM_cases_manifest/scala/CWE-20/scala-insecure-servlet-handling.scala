import javax.servlet.http.{HttpServlet, HttpServletRequest, HttpServletResponse}
import javax.servlet.annotation.WebServlet
import org.owasp.encoder.Encode
import org.apache.commons.text.StringEscapeUtils
import scala.util.{Try, Success, Failure}
import org.owasp.html.PolicyFactory
import org.owasp.html.Sanitizers

// True Positive Examples (Vulnerable Code)

@WebServlet(Array("/bad1"))
class bad_case_1 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val userInput = request.getParameter("username")
    response.setContentType("text/html")
    val out = response.getWriter
    // ruleid: scala-insecure-servlet-handling
    out.println("<html><body>Hello, " + userInput + "!</body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad2"))
class bad_case_2 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val comment = request.getParameter("comment")
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ruleid: scala-insecure-servlet-handling
    out.println("<div class='comment'>" + comment + "</div>")
    out.println("</body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad3"))
class bad_case_3 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val searchTerm = request.getParameter("q")
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ruleid: scala-insecure-servlet-handling
    out.println(s"<h2>Search results for: $searchTerm</h2>")
    out.println("</body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad4"))
class bad_case_4 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val userAgent = request.getHeader("User-Agent")
    response.setContentType("text/html")
    val out = response.getWriter
    // ruleid: scala-insecure-servlet-handling
    out.println(s"<html><body>Your browser: $userAgent</body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad5"))
class bad_case_5 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val referer = request.getHeader("Referer")
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ruleid: scala-insecure-servlet-handling
    out.println(s"<p>You came from: $referer</p>")
    out.println("</body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad6"))
class bad_case_6 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val cookie = request.getHeader("Cookie")
    response.setContentType("text/html")
    val out = response.getWriter
    // ruleid: scala-insecure-servlet-handling
    out.println("<html><body><div id='debug'>Cookie: " + cookie + "</div></body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad7"))
class bad_case_7 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val email = request.getParameter("email")
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ruleid: scala-insecure-servlet-handling
    out.println(s"<p>Your email address ($email) has been registered.</p>")
    out.println("</body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad8"))
class bad_case_8 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val id = request.getParameter("id")
    response.setContentType("text/html")
    val out = response.getWriter
    // ruleid: scala-insecure-servlet-handling
    out.println(s"<html><body><div data-user-id='$id'>User Profile</div></body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad9"))
class bad_case_9 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val errorMsg = request.getParameter("error")
    if (errorMsg != null) {
      response.setContentType("text/html")
      val out = response.getWriter
      out.println("<html><body>")
      // ruleid: scala-insecure-servlet-handling
      out.println(s"<div class='error'>Error: $errorMsg</div>")
      out.println("</body></html>")
      out.close()
    }
  }
}

@WebServlet(Array("/bad10"))
class bad_case_10 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val redirectUrl = request.getParameter("redirect")
    response.setContentType("text/html")
    val out = response.getWriter
    // ruleid: scala-insecure-servlet-handling
    out.println(s"<html><body><a href='$redirectUrl'>Click here to continue</a></body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad11"))
class bad_case_11 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val script = request.getParameter("customJs")
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ruleid: scala-insecure-servlet-handling
    out.println(s"<script>$script</script>")
    out.println("</body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad12"))
class bad_case_12 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val style = request.getParameter("theme")
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html>")
    // ruleid: scala-insecure-servlet-handling
    out.println(s"<style>$style</style>")
    out.println("<body>Theme applied!</body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad13"))
class bad_case_13 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val jsonData = request.getParameter("data")
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ruleid: scala-insecure-servlet-handling
    out.println(s"<div data-json='$jsonData'></div>")
    out.println("</body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad14"))
class bad_case_14 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val username = request.getParameter("user")
    val message = s"Welcome back, $username!"
    response.setContentType("text/html")
    val out = response.getWriter
    // ruleid: scala-insecure-servlet-handling
    out.println(s"<html><body><h1>$message</h1></body></html>")
    out.close()
  }
}

@WebServlet(Array("/bad15"))
class bad_case_15 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val htmlContent = request.getParameter("content")
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ruleid: scala-insecure-servlet-handling
    out.println(s"<div class='user-content'>$htmlContent</div>")
    out.println("</body></html>")
    out.close()
  }
}

// True Negative Examples (Secure Code)

@WebServlet(Array("/good1"))
class good_case_1 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val userInput = request.getParameter("username")
    response.setContentType("text/html")
    val out = response.getWriter
    // ok: scala-insecure-servlet-handling
    out.println("<html><body>Hello, " + Encode.forHtml(userInput) + "!</body></html>")
    out.close()
  }
}

@WebServlet(Array("/good2"))
class good_case_2 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val comment = request.getParameter("comment")
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ok: scala-insecure-servlet-handling
    out.println("<div class='comment'>" + StringEscapeUtils.escapeHtml4(comment) + "</div>")
    out.println("</body></html>")
    out.close()
  }
}

@WebServlet(Array("/good3"))
class good_case_3 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val searchTerm = request.getParameter("q")
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ok: scala-insecure-servlet-handling
    out.println(s"<h2>Search results for: ${Encode.forHtml(searchTerm)}</h2>")
    out.println("</body></html>")
    out.close()
  }
}

@WebServlet(Array("/good4"))
class good_case_4 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val userAgent = request.getHeader("User-Agent")
    response.setContentType("text/html")
    val out = response.getWriter
    // ok: scala-insecure-servlet-handling
    out.println(s"<html><body>Your browser: ${StringEscapeUtils.escapeHtml4(userAgent)}</body></html>")
    out.close()
  }
}

@WebServlet(Array("/good5"))
class good_case_5 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val referer = request.getHeader("Referer")
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ok: scala-insecure-servlet-handling
    out.println(s"<p>You came from: ${Encode.forHtml(referer)}</p>")
    out.println("</body></html>")
    out.close()
  }
}

@WebServlet(Array("/good6"))
class good_case_6 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val cookie = request.getHeader("Cookie")
    response.setContentType("text/html")
    val out = response.getWriter
    // ok: scala-insecure-servlet-handling
    out.println("<html><body><div id='debug'>Cookie: " + Encode.forHtml(cookie) + "</div></body></html>")
    out.close()
  }
}

@WebServlet(Array("/good7"))
class good_case_7 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val email = request.getParameter("email")
    // Validate email format
    val emailPattern = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$".r
    if (emailPattern.findFirstMatchIn(email).isEmpty) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid email format")
      return
    }
    
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ok: scala-insecure-servlet-handling
    out.println(s"<p>Your email address (${StringEscapeUtils.escapeHtml4(email)}) has been registered.</p>")
    out.println("</body></html>")
    out.close()
  }
}

@WebServlet(Array("/good8"))
class good_case_8 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val id = request.getParameter("id")
    // Validate id is numeric
    val idPattern = "^[0-9]+$".r
    if (idPattern.findFirstMatchIn(id).isEmpty) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid ID format")
      return
    }
    
    response.setContentType("text/html")
    val out = response.getWriter
    // ok: scala-insecure-servlet-handling
    out.println(s"<html><body><div data-user-id='${Encode.forHtmlAttribute(id)}'>User Profile</div></body></html>")
    out.close()
  }
}

@WebServlet(Array("/good9"))
class good_case_9 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val errorMsg = request.getParameter("error")
    if (errorMsg != null) {
      response.setContentType("text/html")
      val out = response.getWriter
      out.println("<html><body>")
      // ok: scala-insecure-servlet-handling
      out.println(s"<div class='error'>Error: ${Encode.forHtml(errorMsg)}</div>")
      out.println("</body></html>")
      out.close()
    }
  }
}

@WebServlet(Array("/good10"))
class good_case_10 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val redirectUrl = request.getParameter("redirect")
    // Validate URL
    val allowedDomains = List("example.com", "trusted-site.org")
    val isValid = Try {
      val url = new java.net.URL(redirectUrl)
      allowedDomains.exists(domain => url.getHost.endsWith(domain))
    }.getOrElse(false)
    
    if (!isValid) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid redirect URL")
      return
    }
    
    response.setContentType("text/html")
    val out = response.getWriter
    // ok: scala-insecure-servlet-handling
    out.println(s"<html><body><a href='${Encode.forHtmlAttribute(redirectUrl)}'>Click here to continue</a></body></html>")
    out.close()
  }
}

@WebServlet(Array("/good11"))
class good_case_11 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    // Instead of accepting arbitrary JavaScript, use a predefined set of options
    val scriptOption = request.getParameter("scriptOption")
    val allowedScripts = Map(
      "greeting" -> "alert('Hello, welcome to our site!');",
      "timer" -> "startTimer(60);",
      "theme" -> "applyTheme('dark');"
    )
    
    val safeScript = allowedScripts.getOrElse(scriptOption, "console.log('Invalid option');")
    
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ok: scala-insecure-servlet-handling
    out.println(s"<script>$safeScript</script>")
    out.println("</body></html>")
    out.close()
  }
}

@WebServlet(Array("/good12"))
class good_case_12 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    // Instead of accepting arbitrary CSS, use predefined themes
    val theme = request.getParameter("theme")
    val allowedThemes = Map(
      "light" -> "body { background-color: #fff; color: #333; }",
      "dark" -> "body { background-color: #333; color: #fff; }",
      "blue" -> "body { background-color: #e0f0ff; color: #00366d; }"
    )
    
    val safeStyle = allowedThemes.getOrElse(theme, "body { background-color: #fff; color: #333; }")
    
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html>")
    // ok: scala-insecure-servlet-handling
    out.println(s"<style>$safeStyle</style>")
    out.println("<body>Theme applied!</body></html>")
    out.close()
  }
}

@WebServlet(Array("/good13"))
class good_case_13 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val jsonData = request.getParameter("data")
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ok: scala-insecure-servlet-handling
    out.println(s"<div data-json='${Encode.forHtmlAttribute(jsonData)}'></div>")
    out.println("</body></html>")
    out.close()
  }
}

@WebServlet(Array("/good14"))
class good_case_14 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val username = request.getParameter("user")
    val sanitizedUsername = Encode.forHtml(username)
    val message = s"Welcome back, $sanitizedUsername!"
    response.setContentType("text/html")
    val out = response.getWriter
    // ok: scala-insecure-servlet-handling
    out.println(s"<html><body><h1>$message</h1></body></html>")
    out.close()
  }
}

@WebServlet(Array("/good15"))
class good_case_15 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val htmlContent = request.getParameter("content")
    
    // Use a HTML sanitizer library to clean the content
    val policy = Sanitizers.FORMATTING.and(Sanitizers.BLOCKS).and(Sanitizers.LINKS)
    val sanitizedContent = policy.sanitize(htmlContent)
    
    response.setContentType("text/html")
    val out = response.getWriter
    out.println("<html><body>")
    // ok: scala-insecure-servlet-handling
    out.println(s"<div class='user-content'>$sanitizedContent</div>")
    out.println("</body></html>")
    out.close()
  }
}