import java.io.File
import java.nio.file.{Files, Paths}
import scala.io.Source
import org.apache.commons.io.FilenameUtils
import play.api.mvc._
import play.api.http.HttpEntity
import akka.util.ByteString
import javax.inject.Inject
import scala.concurrent.{ExecutionContext, Future}
import org.apache.commons.io.FileUtils
import java.nio.charset.StandardCharsets
import play.api.libs.json.Json

// True Positive Examples (Vulnerable Code)

class PathTraversalController @Inject()(cc: ControllerComponents)(implicit ec: ExecutionContext) extends AbstractController(cc) {
  
  // Example 1: Basic path traversal with direct file access
  def bad_case_1(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    val file = new File(baseDir + userSuppliedFilename)
    
    // ruleid: scala-absolute-relative-path-traversal
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 2: Path traversal with nio.file.Paths
  def bad_case_2(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("file").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // ruleid: scala-absolute-relative-path-traversal
    val path = Paths.get(baseDir + userSuppliedFilename)
    if (Files.exists(path)) {
      val content = new String(Files.readAllBytes(path))
      Ok(content)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 3: Path traversal with POST data
  def bad_case_3() = Action(parse.form(Forms.single("filename" -> Forms.text))) { request =>
    val userSuppliedFilename = request.body
    val baseDir = "/var/www/files/"
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(baseDir + userSuppliedFilename)
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 4: Path traversal with header value
  def bad_case_4(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.headers.get("X-Filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(baseDir, userSuppliedFilename)
    if (file.exists() && file.isFile) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 5: Path traversal with string concatenation and variable
  def bad_case_5(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("document").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    val filePath = baseDir + userSuppliedFilename
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(filePath)
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 6: Path traversal with cookie value
  def bad_case_6(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.cookies.get("filename").map(_.value).getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(baseDir + userSuppliedFilename)
    if (file.exists()) {
      val fileContent = FileUtils.readFileToString(file, StandardCharsets.UTF_8)
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 7: Path traversal with path parameter
  def bad_case_7(filename: String) = Action { request =>
    val baseDir = "/var/www/files/"
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(baseDir + filename)
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 8: Path traversal with JSON body
  def bad_case_8() = Action(parse.json) { request =>
    val userSuppliedFilename = (request.body \ "filename").as[String]
    val baseDir = "/var/www/files/"
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(baseDir + userSuppliedFilename)
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 9: Path traversal with string interpolation
  def bad_case_9(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(s"$baseDir$userSuppliedFilename")
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 10: Path traversal with file writing
  def bad_case_10(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val content = request.getQueryString("content").getOrElse("")
    val baseDir = "/var/www/files/"
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(baseDir + userSuppliedFilename)
    FileUtils.writeStringToFile(file, content, StandardCharsets.UTF_8)
    Ok("File written successfully")
  }
  
  // Example 11: Path traversal with conditional logic
  def bad_case_11(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    val extension = if (userSuppliedFilename.contains(".")) "" else ".txt"
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(baseDir + userSuppliedFilename + extension)
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 12: Path traversal with multiple parameters
  def bad_case_12(request: Request[AnyContent]) = Action {
    val folder = request.getQueryString("folder").getOrElse("default")
    val filename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(baseDir + folder + "/" + filename)
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 13: Path traversal with partial validation
  def bad_case_13(request: Request[AnyContent]) = Action {
    var userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // Incomplete validation - still vulnerable
    if (userSuppliedFilename.contains("..")) {
      userSuppliedFilename = userSuppliedFilename.replace("..", "")
    }
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(baseDir + userSuppliedFilename)
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 14: Path traversal with file download
  def bad_case_14(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(baseDir + userSuppliedFilename)
    if (file.exists()) {
      val source = FileUtils.readFileToByteArray(file)
      Result(
        header = ResponseHeader(200, Map(
          CONTENT_DISPOSITION -> s"attachment; filename=${file.getName}"
        )),
        body = HttpEntity.Strict(ByteString(source), Some("application/octet-stream"))
      )
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 15: Path traversal with path normalization attempt
  def bad_case_15(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // Incomplete normalization - still vulnerable
    val normalizedPath = userSuppliedFilename.replace("\\", "/")
    
    // ruleid: scala-absolute-relative-path-traversal
    val file = new File(baseDir + normalizedPath)
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // True Negative Examples (Safe Code)
  
  // Example 1: Safe file access using FilenameUtils.getName
  def good_case_1(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // ok: scala-absolute-relative-path-traversal
    val safeFilename = FilenameUtils.getName(userSuppliedFilename)
    val file = new File(baseDir, safeFilename)
    
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 2: Safe file access with whitelist validation
  def good_case_2(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    val allowedFiles = Set("file1.txt", "file2.txt", "file3.txt")
    
    // ok: scala-absolute-relative-path-traversal
    if (allowedFiles.contains(userSuppliedFilename)) {
      val file = new File(baseDir, userSuppliedFilename)
      if (file.exists()) {
        val fileContent = Source.fromFile(file).mkString
        Ok(fileContent)
      } else {
        NotFound("File not found")
      }
    } else {
      BadRequest("Invalid filename")
    }
  }
  
  // Example 3: Safe file access with regex validation
  def good_case_3(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // ok: scala-absolute-relative-path-traversal
    if (userSuppliedFilename.matches("[a-zA-Z0-9_-]+\\.[a-zA-Z0-9]+")) {
      val file = new File(baseDir, userSuppliedFilename)
      if (file.exists()) {
        val fileContent = Source.fromFile(file).mkString
        Ok(fileContent)
      } else {
        NotFound("File not found")
      }
    } else {
      BadRequest("Invalid filename format")
    }
  }
  
  // Example 4: Safe file access with canonical path validation
  def good_case_4(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = new File("/var/www/files/")
    val requestedFile = new File(baseDir, userSuppliedFilename)
    
    // ok: scala-absolute-relative-path-traversal
    val canonicalBasePath = baseDir.getCanonicalPath
    val canonicalRequestedPath = requestedFile.getCanonicalPath
    
    if (canonicalRequestedPath.startsWith(canonicalBasePath)) {
      if (requestedFile.exists()) {
        val fileContent = Source.fromFile(requestedFile).mkString
        Ok(fileContent)
      } else {
        NotFound("File not found")
      }
    } else {
      BadRequest("Invalid file path")
    }
  }
  
  // Example 5: Safe file access with FilenameUtils for POST data
  def good_case_5() = Action(parse.form(Forms.single("filename" -> Forms.text))) { request =>
    val userSuppliedFilename = request.body
    val baseDir = "/var/www/files/"
    
    // ok: scala-absolute-relative-path-traversal
    val safeFilename = FilenameUtils.getName(userSuppliedFilename)
    val file = new File(baseDir, safeFilename)
    
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 6: Safe file access with header value and FilenameUtils
  def good_case_6(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.headers.get("X-Filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // ok: scala-absolute-relative-path-traversal
    val safeFilename = FilenameUtils.getName(userSuppliedFilename)
    val file = new File(baseDir, safeFilename)
    
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 7: Safe file access with path parameter and FilenameUtils
  def good_case_7(filename: String) = Action { request =>
    val baseDir = "/var/www/files/"
    
    // ok: scala-absolute-relative-path-traversal
    val safeFilename = FilenameUtils.getName(filename)
    val file = new File(baseDir, safeFilename)
    
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 8: Safe file access with JSON body and FilenameUtils
  def good_case_8() = Action(parse.json) { request =>
    val userSuppliedFilename = (request.body \ "filename").as[String]
    val baseDir = "/var/www/files/"
    
    // ok: scala-absolute-relative-path-traversal
    val safeFilename = FilenameUtils.getName(userSuppliedFilename)
    val file = new File(baseDir, safeFilename)
    
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 9: Safe file access with UUID generation
  def good_case_9(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    val extension = userSuppliedFilename.split('.').last
    
    // ok: scala-absolute-relative-path-traversal
    val safeFilename = java.util.UUID.randomUUID().toString + "." + extension
    val file = new File(baseDir, safeFilename)
    
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 10: Safe file writing with FilenameUtils
  def good_case_10(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val content = request.getQueryString("content").getOrElse("")
    val baseDir = "/var/www/files/"
    
    // ok: scala-absolute-relative-path-traversal
    val safeFilename = FilenameUtils.getName(userSuppliedFilename)
    val file = new File(baseDir, safeFilename)
    
    FileUtils.writeStringToFile(file, content, StandardCharsets.UTF_8)
    Ok("File written successfully")
  }
  
  // Example 11: Safe file access with ID mapping
  def good_case_11(request: Request[AnyContent]) = Action {
    val fileId = request.getQueryString("id").getOrElse("1")
    val baseDir = "/var/www/files/"
    
    // ok: scala-absolute-relative-path-traversal
    val fileMap = Map(
      "1" -> "file1.txt",
      "2" -> "file2.txt",
      "3" -> "file3.txt"
    )
    
    fileMap.get(fileId) match {
      case Some(filename) =>
        val file = new File(baseDir, filename)
        if (file.exists()) {
          val fileContent = Source.fromFile(file).mkString
          Ok(fileContent)
        } else {
          NotFound("File not found")
        }
      case None =>
        BadRequest("Invalid file ID")
    }
  }
  
  // Example 12: Safe file access with hardcoded file names
  def good_case_12(request: Request[AnyContent]) = Action {
    val fileType = request.getQueryString("type").getOrElse("text")
    val baseDir = "/var/www/files/"
    
    // ok: scala-absolute-relative-path-traversal
    val filename = fileType match {
      case "text" => "document.txt"
      case "image" => "image.jpg"
      case "pdf" => "document.pdf"
      case _ => "default.txt"
    }
    
    val file = new File(baseDir, filename)
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 13: Safe file access with complete path validation
  def good_case_13(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // ok: scala-absolute-relative-path-traversal
    if (!userSuppliedFilename.contains("..") && 
        !userSuppliedFilename.contains("/") && 
        !userSuppliedFilename.contains("\\") &&
        userSuppliedFilename.matches("[a-zA-Z0-9_.-]+")) {
      
      val file = new File(baseDir, userSuppliedFilename)
      if (file.exists()) {
        val fileContent = Source.fromFile(file).mkString
        Ok(fileContent)
      } else {
        NotFound("File not found")
      }
    } else {
      BadRequest("Invalid filename")
    }
  }
  
  // Example 14: Safe file download with FilenameUtils
  def good_case_14(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // ok: scala-absolute-relative-path-traversal
    val safeFilename = FilenameUtils.getName(userSuppliedFilename)
    val file = new File(baseDir, safeFilename)
    
    if (file.exists()) {
      val source = FileUtils.readFileToByteArray(file)
      Result(
        header = ResponseHeader(200, Map(
          CONTENT_DISPOSITION -> s"attachment; filename=${file.getName}"
        )),
        body = HttpEntity.Strict(ByteString(source), Some("application/octet-stream"))
      )
    } else {
      NotFound("File not found")
    }
  }
  
  // Example 15: Safe file access with path normalization and validation
  def good_case_15(request: Request[AnyContent]) = Action {
    val userSuppliedFilename = request.getQueryString("filename").getOrElse("default.txt")
    val baseDir = "/var/www/files/"
    
    // ok: scala-absolute-relative-path-traversal
    val safeFilename = new File(userSuppliedFilename).getName
    val file = new File(baseDir, safeFilename)
    
    if (file.exists()) {
      val fileContent = Source.fromFile(file).mkString
      Ok(fileContent)
    } else {
      NotFound("File not found")
    }
  }
}