import javax.servlet.http.{HttpServlet, HttpServletRequest, HttpServletResponse}
import java.io.File
import java.nio.file.{Files, Paths, Path}
import scala.util.{Try, Success, Failure}
import scala.io.Source
import play.api.mvc.{Action, Controller, Request, AnyContent}
import play.api.http.{Status, HttpVerbs}
import org.springframework.web.bind.annotation.{RequestMapping, RequestParam, GetMapping, PostMapping}
import org.springframework.stereotype.Controller

// True Positive Examples (Vulnerable Code)

class bad_case_1 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val jspFile = request.getParameter("page")
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher(jspFile).forward(request, response)
  }
}

class bad_case_2 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val template = request.getParameter("template")
    val path = s"/WEB-INF/templates/${template}.jsp"
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher(path).include(request, response)
  }
}

class bad_case_3 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val viewName = request.getParameter("view")
    val userType = request.getParameter("type")
    val viewPath = s"/views/${userType}/${viewName}.jsp"
    // ruleid: scala-inject-file-disclosure
    getServletContext().getRequestDispatcher(viewPath).forward(request, response)
  }
}

@Controller
class bad_case_4 {
  @GetMapping(Array("/view"))
  def viewPage(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val pageName = request.getParameter("page")
    val section = request.getParameter("section")
    val fullPath = s"${section}/${pageName}"
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher(fullPath).forward(request, response)
  }
}

class bad_case_5 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val fileName = request.getHeader("X-File-Name")
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher("/resources/" + fileName).forward(request, response)
  }
}

class bad_case_6 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val cookie = request.getCookies().find(_.getName == "preferred_page")
    val page = cookie.map(_.getValue).getOrElse("default")
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher(page).forward(request, response)
  }
}

class bad_case_7 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val referer = request.getHeader("Referer")
    val lastSegment = referer.substring(referer.lastIndexOf("/") + 1)
    val viewPath = s"/views/${lastSegment}.jsp"
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher(viewPath).forward(request, response)
  }
}

@Controller
class bad_case_8 {
  @PostMapping(Array("/process"))
  def processForm(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val action = request.getParameter("action")
    val result = s"/results/${action}_result.jsp"
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher(result).forward(request, response)
  }
}

class bad_case_9 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val language = request.getLocale.getLanguage
    val page = request.getParameter("page")
    val localizedPage = s"/content/${language}/${page}"
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher(localizedPage).forward(request, response)
  }
}

class bad_case_10 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val queryString = request.getQueryString
    val parts = queryString.split("=")
    val pageName = if (parts.length > 1) parts(1) else "default"
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher("/pages/" + pageName).forward(request, response)
  }
}

@Controller
class bad_case_11 {
  @GetMapping(Array("/admin"))
  def adminPage(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val module = request.getParameter("module")
    val adminPath = s"/admin/${module}/index.jsp"
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher(adminPath).forward(request, response)
  }
}

class bad_case_12 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val pathInfo = request.getPathInfo
    val segments = pathInfo.split("/")
    val resource = segments.lastOption.getOrElse("index")
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher("/content/" + resource).forward(request, response)
  }
}

class bad_case_13 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val userAgent = request.getHeader("User-Agent")
    val deviceType = if (userAgent.contains("Mobile")) "mobile" else "desktop"
    val page = request.getParameter("page")
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher(s"/${deviceType}/${page}.jsp").forward(request, response)
  }
}

class bad_case_14 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val formData = request.getParameterMap
    val nextPage = formData.get("next_page")(0)
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher(nextPage).forward(request, response)
  }
}

class bad_case_15 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val sessionAttr = request.getSession.getAttribute("current_view")
    val viewPath = if (sessionAttr != null) sessionAttr.toString else "default"
    // ruleid: scala-inject-file-disclosure
    request.getRequestDispatcher(viewPath).forward(request, response)
  }
}

// True Negative Examples (Safe Code)

class good_case_1 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val jspFile = request.getParameter("page")
    val path = Paths.get(jspFile).normalize().toString()
    val allowedPages = List("home.jsp", "about.jsp", "contact.jsp")
    // ok: scala-inject-file-disclosure
    if (allowedPages.contains(path)) {
      request.getRequestDispatcher("/WEB-INF/pages/" + path).forward(request, response)
    } else {
      response.sendError(HttpServletResponse.SC_NOT_FOUND)
    }
  }
}

class good_case_2 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val template = request.getParameter("template")
    val normalizedPath = Paths.get(template).normalize().toString()
    val basePath = "/WEB-INF/templates/"
    val fullPath = Paths.get(basePath, normalizedPath).normalize().toString()
    
    // ok: scala-inject-file-disclosure
    if (fullPath.startsWith(basePath)) {
      request.getRequestDispatcher(fullPath).include(request, response)
    } else {
      response.sendError(HttpServletResponse.SC_FORBIDDEN)
    }
  }
}

class good_case_3 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val viewName = request.getParameter("view")
    val userType = request.getParameter("type")
    
    // Validate inputs against whitelist
    val validViews = Set("dashboard", "profile", "settings")
    val validTypes = Set("admin", "user", "guest")
    
    // ok: scala-inject-file-disclosure
    if (validViews.contains(viewName) && validTypes.contains(userType)) {
      val viewPath = s"/views/${userType}/${viewName}.jsp"
      getServletContext().getRequestDispatcher(viewPath).forward(request, response)
    } else {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST)
    }
  }
}

@Controller
class good_case_4 {
  @GetMapping(Array("/view"))
  def viewPage(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val pageName = request.getParameter("page")
    val section = request.getParameter("section")
    
    // Sanitize and validate inputs
    val validSections = Set("public", "private", "shared")
    val validPages = Set("index", "details", "summary")
    
    // ok: scala-inject-file-disclosure
    if (validSections.contains(section) && validPages.contains(pageName)) {
      val fullPath = s"/${section}/${pageName}.jsp"
      request.getRequestDispatcher(fullPath).forward(request, response)
    } else {
      response.sendError(HttpServletResponse.SC_NOT_FOUND)
    }
  }
}

class good_case_5 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val fileName = request.getHeader("X-File-Name")
    val normalizedPath = Paths.get(fileName).normalize().toString()
    
    // Prevent path traversal
    // ok: scala-inject-file-disclosure
    if (!normalizedPath.contains("..") && normalizedPath.matches("[a-zA-Z0-9_-]+\\.jsp")) {
      request.getRequestDispatcher("/resources/" + normalizedPath).forward(request, response)
    } else {
      response.sendError(HttpServletResponse.SC_FORBIDDEN)
    }
  }
}

class good_case_6 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val cookie = request.getCookies().find(_.getName == "preferred_page")
    val page = cookie.map(_.getValue).getOrElse("default")
    
    val allowedPages = Map(
      "home" -> "/pages/home.jsp",
      "profile" -> "/pages/profile.jsp",
      "default" -> "/pages/default.jsp"
    )
    
    // ok: scala-inject-file-disclosure
    allowedPages.get(page) match {
      case Some(validPath) => request.getRequestDispatcher(validPath).forward(request, response)
      case None => request.getRequestDispatcher("/pages/default.jsp").forward(request, response)
    }
  }
}

class good_case_7 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val referer = request.getHeader("Referer")
    val lastSegment = if (referer != null) {
      referer.substring(referer.lastIndexOf("/") + 1)
    } else {
      "index"
    }
    
    // ok: scala-inject-file-disclosure
    val safeSegment = lastSegment.replaceAll("[^a-zA-Z0-9_]", "")
    val viewPath = s"/views/${safeSegment}.jsp"
    
    val allowedPath = Paths.get("/views/").resolve(safeSegment + ".jsp").normalize()
    if (allowedPath.startsWith("/views/")) {
      request.getRequestDispatcher(viewPath).forward(request, response)
    } else {
      response.sendError(HttpServletResponse.SC_FORBIDDEN)
    }
  }
}

@Controller
class good_case_8 {
  @PostMapping(Array("/process"))
  def processForm(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val action = request.getParameter("action")
    
    // Map user input to predefined paths
    val actionMap = Map(
      "save" -> "/results/save_result.jsp",
      "update" -> "/results/update_result.jsp",
      "delete" -> "/results/delete_result.jsp"
    )
    
    // ok: scala-inject-file-disclosure
    actionMap.get(action) match {
      case Some(path) => request.getRequestDispatcher(path).forward(request, response)
      case None => response.sendError(HttpServletResponse.SC_BAD_REQUEST)
    }
  }
}

class good_case_9 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val language = request.getLocale.getLanguage
    val page = request.getParameter("page")
    
    // Validate language and page
    val validLanguages = Set("en", "fr", "es", "de")
    val validPages = Set("home", "about", "contact")
    
    // ok: scala-inject-file-disclosure
    if (validLanguages.contains(language) && validPages.contains(page)) {
      val localizedPage = s"/content/${language}/${page}.jsp"
      request.getRequestDispatcher(localizedPage).forward(request, response)
    } else {
      request.getRequestDispatcher("/content/en/home.jsp").forward(request, response)
    }
  }
}

class good_case_10 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val queryString = request.getQueryString
    val parts = if (queryString != null) queryString.split("=") else Array()
    val pageName = if (parts.length > 1) parts(1) else "default"
    
    // Sanitize and validate
    val sanitizedPage = pageName.replaceAll("[^a-zA-Z0-9_-]", "")
    val basePath = "/pages/"
    
    // ok: scala-inject-file-disclosure
    val fullPath = Paths.get(basePath).resolve(sanitizedPage + ".jsp").normalize().toString()
    if (fullPath.startsWith(basePath)) {
      request.getRequestDispatcher(fullPath).forward(request, response)
    } else {
      response.sendError(HttpServletResponse.SC_FORBIDDEN)
    }
  }
}

@Controller
class good_case_11 {
  @GetMapping(Array("/admin"))
  def adminPage(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val module = request.getParameter("module")
    
    // Whitelist of allowed admin modules
    val allowedModules = Set("users", "reports", "settings")
    
    // ok: scala-inject-file-disclosure
    if (allowedModules.contains(module)) {
      val adminPath = s"/admin/${module}/index.jsp"
      request.getRequestDispatcher(adminPath).forward(request, response)
    } else {
      response.sendError(HttpServletResponse.SC_FORBIDDEN)
    }
  }
}

class good_case_12 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val pathInfo = request.getPathInfo
    val segments = if (pathInfo != null) pathInfo.split("/") else Array()
    val resource = segments.lastOption.getOrElse("index")
    
    // Sanitize and validate
    val sanitizedResource = resource.replaceAll("[^a-zA-Z0-9_-]", "")
    val contentDir = "/content/"
    
    // ok: scala-inject-file-disclosure
    val fullPath = Paths.get(contentDir).resolve(sanitizedResource + ".jsp").normalize().toString()
    if (fullPath.startsWith(contentDir)) {
      request.getRequestDispatcher(fullPath).forward(request, response)
    } else {
      response.sendError(HttpServletResponse.SC_FORBIDDEN)
    }
  }
}

class good_case_13 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val userAgent = request.getHeader("User-Agent")
    val deviceType = if (userAgent != null && userAgent.contains("Mobile")) "mobile" else "desktop"
    val page = request.getParameter("page")
    
    // Validate page parameter
    val validPages = Set("home", "products", "contact")
    
    // ok: scala-inject-file-disclosure
    if (validPages.contains(page)) {
      request.getRequestDispatcher(s"/${deviceType}/${page}.jsp").forward(request, response)
    } else {
      request.getRequestDispatcher(s"/${deviceType}/home.jsp").forward(request, response)
    }
  }
}

class good_case_14 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val formData = request.getParameterMap
    val nextPageArray = formData.get("next_page")
    val nextPage = if (nextPageArray != null && nextPageArray.length > 0) nextPageArray(0) else "index"
    
    // Map to predefined paths
    val pageMap = Map(
      "checkout" -> "/secure/checkout.jsp",
      "confirm" -> "/secure/confirmation.jsp",
      "cancel" -> "/public/canceled.jsp",
      "index" -> "/public/index.jsp"
    )
    
    // ok: scala-inject-file-disclosure
    pageMap.get(nextPage) match {
      case Some(path) => request.getRequestDispatcher(path).forward(request, response)
      case None => request.getRequestDispatcher("/public/index.jsp").forward(request, response)
    }
  }
}

class good_case_15 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val sessionAttr = request.getSession.getAttribute("current_view")
    val viewPath = if (sessionAttr != null) sessionAttr.toString else "default"
    
    // Validate path
    val normalizedPath = Paths.get(viewPath).normalize().toString()
    val basePath = "/WEB-INF/views/"
    
    // ok: scala-inject-file-disclosure
    val fullPath = Paths.get(basePath, normalizedPath + ".jsp").normalize().toString()
    if (fullPath.startsWith(basePath)) {
      request.getRequestDispatcher(fullPath).forward(request, response)
    } else {
      request.getRequestDispatcher("/WEB-INF/views/default.jsp").forward(request, response)
    }
  }
}