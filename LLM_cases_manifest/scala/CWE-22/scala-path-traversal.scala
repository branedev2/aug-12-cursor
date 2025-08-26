import java.io.{File, FileInputStream, FileReader, BufferedReader}
import java.nio.file.{Files, Paths, Path}
import org.apache.commons.io.FilenameUtils
import scala.io.Source
import play.api.mvc._
import play.api.http._
import play.api.libs.json._
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.{HttpRequest, StatusCodes}
import org.springframework.web.bind.annotation._
import org.springframework.stereotype.Controller
import org.springframework.http.ResponseEntity
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
// {fact rule=path-traversal@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(request: play.api.mvc.Request[AnyContent]): Unit = {
  val fileName = request.getQueryString("file").getOrElse("default.txt")
  // ruleid: scala-path-traversal
  val file = new File(s"/var/data/${fileName}")
  val content = Source.fromFile(file).getLines().mkString("\n")
  println(content)
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_2(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userId = request.getQueryString("id").getOrElse("anonymous")
  val reportName = request.getQueryString("report").getOrElse("summary.pdf")
  val path = s"/app/reports/${userId}/${reportName}"
  // ruleid: scala-path-traversal
  val fileStream = new FileInputStream(path)
  // Process the file stream
  fileStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_3(request: HttpServletRequest): Unit = {
  val template = request.getParameter("template")
  // ruleid: scala-path-traversal
  val reader = new BufferedReader(new FileReader(s"templates/${template}"))
  val content = Iterator.continually(reader.readLine()).takeWhile(_ != null).mkString("\n")
  reader.close()
}
// {/fact}

def bad_case_4(): akka.http.scaladsl.server.Route = {
  path("download") {
    get {
      parameter("file") { fileName =>
        // ruleid: scala-path-traversal
        val filePath = s"public/downloads/$fileName"
        getFromFile(filePath)
      }
    }
  }
}

@Controller
class bad_case_5 {
  @GetMapping(Array("/api/files"))
  def getFile(@RequestParam("name") fileName: String): ResponseEntity[Array[Byte]] = {
    // ruleid: scala-path-traversal
    val file = new File(s"data/files/$fileName")
    val content = Files.readAllBytes(file.toPath)
    ResponseEntity.ok(content)
  }
}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_6(request: play.api.mvc.Request[AnyContent]): Unit = {
  val jsonBody = request.body.asJson.get
  val configFile = (jsonBody \ "config").as[String]
  // ruleid: scala-path-traversal
  val configData = Files.readAllBytes(Paths.get(s"configs/$configFile"))
  // Process config data
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_7(request: HttpServletRequest): Unit = {
  val theme = request.getHeader("X-Theme")
  val language = request.getParameter("lang")
  // ruleid: scala-path-traversal
  val themePath = new File(s"themes/$theme/$language/style.css")
  val themeContent = Files.readAllBytes(themePath.toPath)
  // Use theme content
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_8(request: play.api.mvc.Request[AnyContent]): Unit = {
  val formData = request.body.asFormUrlEncoded
  val documentPath = formData.get("document").flatMap(_.headOption).getOrElse("default")
  // ruleid: scala-path-traversal
  val document = Source.fromFile(s"/var/www/documents/$documentPath")
  val content = document.mkString
  document.close()
}
// {/fact}

def bad_case_9(): akka.http.scaladsl.server.Route = {
  path("profile" / Segment) { username =>
    get {
      // ruleid: scala-path-traversal
      val profilePath = s"users/profiles/$username/profile.json"
      val profileData = Source.fromFile(profilePath).mkString
      complete(profileData)
    }
  }
}

@Controller
class bad_case_10 {
  @PostMapping(Array("/api/logs"))
  def getLogs(request: HttpServletRequest): ResponseEntity[String] = {
    val logType = request.getParameter("type")
    val date = request.getParameter("date")
    // ruleid: scala-path-traversal
    val logFile = new File(s"/var/logs/$logType/$date.log")
    val logContent = Source.fromFile(logFile).getLines().mkString("\n")
    ResponseEntity.ok(logContent)
  }
}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_11(request: play.api.mvc.Request[AnyContent]): Unit = {
  val cookie = request.cookies.get("preferences")
  val theme = cookie.map(_.value).getOrElse("default")
  // ruleid: scala-path-traversal
  val themeConfig = Files.readAllLines(Paths.get(s"themes/$theme.config"))
  // Process theme config
}
// {/fact}

def bad_case_12(): akka.http.scaladsl.server.Route = {
  path("images") {
    get {
      parameters("category", "name") { (category, name) =>
        // ruleid: scala-path-traversal
        val imagePath = s"resources/images/$category/$name"
        getFromFile(imagePath)
      }
    }
  }
}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_13(request: HttpServletRequest): Unit = {
  val module = request.getParameter("module")
  val action = request.getParameter("action")
  // ruleid: scala-path-traversal
  val moduleScript = new File(s"modules/$module/$action.scala")
  val scriptContent = Source.fromFile(moduleScript).getLines().mkString("\n")
  // Execute script content
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_14(request: play.api.mvc.Request[AnyContent]): Unit = {
  val jsonBody = request.body.asJson.get
  val backupFile = (jsonBody \ "backup").as[String]
  // ruleid: scala-path-traversal
  val backupPath = Paths.get(s"backups/$backupFile")
  val backupData = Files.readAllBytes(backupPath)
  // Process backup data
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_15(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val relativePath = request.getParameter("path")
  if (relativePath != null) {
    // ruleid: scala-path-traversal
    val file = new File(s"content/$relativePath")
    val content = Files.readAllBytes(file.toPath)
    response.getOutputStream.write(content)
  }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// True Negatives (Secure Code)

def good_case_1(request: play.api.mvc.Request[AnyContent]): Unit = {
  val fileName = request.getQueryString("file").getOrElse("default.txt")
  val normalizedPath = FilenameUtils.normalize(fileName)
  
  if (normalizedPath != null && !normalizedPath.contains("..")) {
    // ok: scala-path-traversal
    val file = new File(s"/var/data/${normalizedPath}")
    val content = Source.fromFile(file).getLines().mkString("\n")
    println(content)
  }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_2(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userId = request.getQueryString("id").getOrElse("anonymous")
  val reportName = request.getQueryString("report").getOrElse("summary.pdf")
  
  val allowedReports = Set("summary.pdf", "details.pdf", "stats.pdf")
  val allowedUsers = Set("user1", "user2", "admin")
  
  if (allowedReports.contains(reportName) && allowedUsers.contains(userId)) {
    // ok: scala-path-traversal
    val path = s"/app/reports/${userId}/${reportName}"
    val fileStream = new FileInputStream(path)
    // Process the file stream
    fileStream.close()
  }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_3(request: HttpServletRequest): Unit = {
  val template = request.getParameter("template")
  val safeTemplate = FilenameUtils.getName(template) // Get just the filename, no path
  val allowedTemplates = Set("basic.html", "advanced.html", "report.html")
  
  if (allowedTemplates.contains(safeTemplate)) {
    // ok: scala-path-traversal
    val reader = new BufferedReader(new FileReader(s"templates/${safeTemplate}"))
    val content = Iterator.continually(reader.readLine()).takeWhile(_ != null).mkString("\n")
    reader.close()
  }
}
// {/fact}

def good_case_4(): akka.http.scaladsl.server.Route = {
  path("download") {
    get {
      parameter("file") { fileName =>
        val safeFileName = FilenameUtils.getName(fileName)
        val baseDir = new File("public/downloads")
        
        // ok: scala-path-traversal
        val filePath = new File(baseDir, safeFileName).getCanonicalPath
        if (filePath.startsWith(baseDir.getCanonicalPath)) {
          getFromFile(filePath)
        } else {
          complete(StatusCodes.Forbidden)
        }
      }
    }
  }
}

@Controller
class good_case_5 {
  @GetMapping(Array("/api/files"))
  def getFile(@RequestParam("name") fileName: String): ResponseEntity[Array[Byte]] = {
    val allowedExtensions = Set(".txt", ".pdf", ".doc")
    val extension = fileName.substring(fileName.lastIndexOf("."))
    
    if (allowedExtensions.contains(extension) && !fileName.contains("/") && !fileName.contains("\\")) {
      // ok: scala-path-traversal
      val file = new File(s"data/files/${fileName}")
      val content = Files.readAllBytes(file.toPath)
      ResponseEntity.ok(content)
    } else {
      ResponseEntity.badRequest().build()
    }
  }
}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_6(request: play.api.mvc.Request[AnyContent]): Unit = {
  val jsonBody = request.body.asJson.get
  val configFile = (jsonBody \ "config").as[String]
  
  val validConfigs = Map(
    "app" -> "app_config.json",
    "system" -> "system_config.json",
    "user" -> "user_config.json"
  )
  
  validConfigs.get(configFile).foreach { safeConfigFile =>
    // ok: scala-path-traversal
    val configData = Files.readAllBytes(Paths.get(s"configs/$safeConfigFile"))
    // Process config data
  }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_7(request: HttpServletRequest): Unit = {
  val theme = request.getHeader("X-Theme")
  val language = request.getParameter("lang")
  
  val allowedThemes = Set("light", "dark", "blue")
  val allowedLanguages = Set("en", "fr", "es", "de")
  
  if (allowedThemes.contains(theme) && allowedLanguages.contains(language)) {
    // ok: scala-path-traversal
    val themePath = new File(s"themes/$theme/$language/style.css")
    val themeContent = Files.readAllBytes(themePath.toPath)
    // Use theme content
  }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_8(request: play.api.mvc.Request[AnyContent]): Unit = {
  val formData = request.body.asFormUrlEncoded
  val documentPath = formData.get("document").flatMap(_.headOption).getOrElse("default")
  
  val normalizedPath = FilenameUtils.normalize(documentPath)
  val baseDir = new File("/var/www/documents").getCanonicalPath
  
  if (normalizedPath != null) {
    // ok: scala-path-traversal
    val documentFile = new File(s"/var/www/documents/$normalizedPath")
    if (documentFile.getCanonicalPath.startsWith(baseDir)) {
      val document = Source.fromFile(documentFile)
      val content = document.mkString
      document.close()
    }
  }
}
// {/fact}

def good_case_9(): akka.http.scaladsl.server.Route = {
  path("profile" / Segment) { username =>
    get {
      val sanitizedUsername = username.replaceAll("[^a-zA-Z0-9]", "")
      
      // ok: scala-path-traversal
      val profilePath = s"users/profiles/$sanitizedUsername/profile.json"
      val profileFile = new File(profilePath)
      
      if (profileFile.exists() && profileFile.isFile) {
        val profileData = Source.fromFile(profileFile).mkString
        complete(profileData)
      } else {
        complete(StatusCodes.NotFound)
      }
    }
  }
}

@Controller
class good_case_10 {
  @PostMapping(Array("/api/logs"))
  def getLogs(request: HttpServletRequest): ResponseEntity[String] = {
    val logType = request.getParameter("type")
    val date = request.getParameter("date")
    
    val validLogTypes = Set("access", "error", "system", "debug")
    val datePattern = "^\\d{4}-\\d{2}-\\d{2}$".r
    
    if (validLogTypes.contains(logType) && datePattern.matches(date)) {
      // ok: scala-path-traversal
      val logFile = new File(s"/var/logs/$logType/$date.log")
      val logContent = Source.fromFile(logFile).getLines().mkString("\n")
      ResponseEntity.ok(logContent)
    } else {
      ResponseEntity.badRequest().build()
    }
  }
}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_11(request: play.api.mvc.Request[AnyContent]): Unit = {
  val cookie = request.cookies.get("preferences")
  val theme = cookie.map(_.value).getOrElse("default")
  
  val allowedThemes = Set("default", "light", "dark", "high-contrast")
  
  if (allowedThemes.contains(theme)) {
    // ok: scala-path-traversal
    val themeConfig = Files.readAllLines(Paths.get(s"themes/$theme.config"))
    // Process theme config
  }
}
// {/fact}

def good_case_12(): akka.http.scaladsl.server.Route = {
  path("images") {
    get {
      parameters("category", "name") { (category, name) =>
        val safeCategory = FilenameUtils.normalize(category)
        val safeName = FilenameUtils.getName(name) // Only get the filename part
        
        if (safeCategory != null && !safeCategory.contains("..")) {
          // ok: scala-path-traversal
          val baseDir = new File("resources/images").getCanonicalPath
          val imagePath = new File(s"resources/images/$safeCategory/$safeName").getCanonicalPath
          
          if (imagePath.startsWith(baseDir)) {
            getFromFile(imagePath)
          } else {
            complete(StatusCodes.Forbidden)
          }
        } else {
          complete(StatusCodes.BadRequest)
        }
      }
    }
  }
}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_13(request: HttpServletRequest): Unit = {
  val module = request.getParameter("module")
  val action = request.getParameter("action")
  
  val validModules = Map(
    "users" -> Set("list", "add", "edit"),
    "reports" -> Set("generate", "view", "export"),
    "settings" -> Set("general", "security", "notifications")
  )
  
  validModules.get(module).flatMap { validActions =>
    if (validActions.contains(action)) {
      // ok: scala-path-traversal
      val moduleScript = new File(s"modules/$module/$action.scala")
      Some(Source.fromFile(moduleScript).getLines().mkString("\n"))
    } else None
  }
  // Process script content if available
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_14(request: play.api.mvc.Request[AnyContent]): Unit = {
  val jsonBody = request.body.asJson.get
  val backupFile = (jsonBody \ "backup").as[String]
  
  // Validate filename format (only alphanumeric with specific extensions)
  if (backupFile.matches("^[a-zA-Z0-9_-]+\\.(zip|tar|gz|bak)$")) {
    // ok: scala-path-traversal
    val backupPath = Paths.get(s"backups/$backupFile")
    val backupData = Files.readAllBytes(backupPath)
    // Process backup data
  }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_15(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val relativePath = request.getParameter("path")
  
  if (relativePath != null) {
    val normalizedPath = FilenameUtils.normalize(relativePath)
    val baseDir = new File("content").getCanonicalPath
    
    if (normalizedPath != null && !normalizedPath.contains("..")) {
      // ok: scala-path-traversal
      val file = new File(s"content/$normalizedPath")
      
      if (file.getCanonicalPath.startsWith(baseDir) && file.isFile) {
        val content = Files.readAllBytes(file.toPath)
        response.getOutputStream.write(content)
      }
    }
  }
}
// {/fact}