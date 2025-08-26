import org.apache.commons.io.FilenameUtils
import java.io.{File, FileInputStream, FileOutputStream}
import java.nio.file.{Files, Paths}
import scala.io.Source
import play.api.mvc._
import play.api.http._
import play.api.libs.json._
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.{HttpRequest, StatusCodes}
import scala.util.{Try, Success, Failure}
// {fact rule=path-traversal@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(request: play.api.mvc.Request[AnyContent]): File = {
  val userProvidedPath = request.getQueryString("file").getOrElse("default.txt")
  val baseDir = "/app/files/"
  val filePath = baseDir + userProvidedPath
  
  // ruleid: scala-filename-utils
  val normalizedPath = FilenameUtils.getName(filePath)
  new File(baseDir, normalizedPath)
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_2(request: play.api.mvc.Request[AnyContent]): String = {
  val userInput = request.body.asFormUrlEncoded.get("filepath").head
  val basePath = "/var/data/"
  
  // ruleid: scala-filename-utils
  val extension = FilenameUtils.getExtension(userInput)
  val filename = FilenameUtils.getBaseName(userInput)
  val fullPath = basePath + filename + "." + extension
  
  Source.fromFile(fullPath).getLines().mkString("\n")
}
// {/fact}

def bad_case_3()(implicit request: play.api.mvc.Request[AnyContent]): Array[Byte] = {
  val path = request.headers.get("X-File-Path").getOrElse("default.txt")
  val storageDir = "/storage/documents/"
  
  // ruleid: scala-filename-utils
  val pathWithoutExtension = FilenameUtils.removeExtension(path)
  val fullPath = storageDir + pathWithoutExtension + ".pdf"
  
  Files.readAllBytes(Paths.get(fullPath))
}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_4(request: HttpRequest): String = {
  val userPath = request.uri.query().get("path").getOrElse("default")
  val baseDir = "/app/resources/"
  
  // ruleid: scala-filename-utils
  val separatorsToUnix = FilenameUtils.separatorsToUnix(userPath)
  val fullPath = baseDir + separatorsToUnix
  
  Source.fromFile(fullPath).getLines().mkString("\n")
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_5(request: play.api.mvc.Request[AnyContent]): File = {
  val fileName = request.body.asJson.get("file").as[String]
  val baseDir = "/var/www/uploads/"
  
  // ruleid: scala-filename-utils
  val pathNoEndSeparator = FilenameUtils.getPathNoEndSeparator(fileName)
  val fullPath = baseDir + pathNoEndSeparator + "/index.html"
  
  new File(fullPath)
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_6(request: play.api.mvc.Request[AnyContent]): String = {
  val userInput = request.getQueryString("template").getOrElse("default")
  val templatesDir = "/app/templates/"
  
  // ruleid: scala-filename-utils
  val fullPathName = FilenameUtils.getFullPathNoEndSeparator(userInput)
  val filePath = templatesDir + fullPathName + ".tmpl"
  
  Source.fromFile(filePath).getLines().mkString("\n")
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_7(request: play.api.mvc.Request[AnyContent]): Unit = {
  val sourceFile = request.getQueryString("source").getOrElse("default.txt")
  val destFile = request.getQueryString("dest").getOrElse("output.txt")
  val baseDir = "/app/data/"
  
  // ruleid: scala-filename-utils
  val sourcePath = baseDir + FilenameUtils.getPath(sourceFile)
  val destPath = baseDir + FilenameUtils.getPath(destFile)
  
  val source = new FileInputStream(sourcePath)
  val dest = new FileOutputStream(destPath)
  
  try {
    val buffer = new Array[Byte](1024)
    var length = 0
    while ({ length = source.read(buffer); length > 0 }) {
      dest.write(buffer, 0, length)
    }
  } finally {
    source.close()
    dest.close()
  }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_8(request: HttpRequest): File = {
  val userPath = request.uri.query().get("config").getOrElse("settings.conf")
  val configDir = "/etc/app/"
  
  // ruleid: scala-filename-utils
  val prefix = FilenameUtils.getPrefix(userPath)
  val path = if (prefix.isEmpty) userPath else userPath.substring(prefix.length)
  val fullPath = configDir + path
  
  new File(fullPath)
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_9(request: play.api.mvc.Request[AnyContent]): String = {
  val relativePath = request.body.asFormUrlEncoded.get("path").head
  val baseDir = "/home/user/documents/"
  
  // ruleid: scala-filename-utils
  val normalizedPath = FilenameUtils.separatorsToSystem(relativePath)
  val fullPath = baseDir + normalizedPath
  
  Source.fromFile(fullPath).getLines().mkString("\n")
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_10(request: play.api.mvc.Request[AnyContent]): File = {
  val userInput = request.cookies.get("file_path").map(_.value).getOrElse("default.txt")
  val baseDir = "/var/app/files/"
  
  // ruleid: scala-filename-utils
  val pathNoEndSeparator = FilenameUtils.getPathNoEndSeparator(userInput)
  val fullPath = baseDir + pathNoEndSeparator + "/data.bin"
  
  new File(fullPath)
}
// {/fact}

def bad_case_11(request: HttpRequest): Array[Byte] = {
  val fileName = request.uri.query().get("file").getOrElse("default.txt")
  val baseDir = "/opt/data/"
  
  // ruleid: scala-filename-utils
  val path = FilenameUtils.getFullPath(fileName)
  val fullPath = baseDir + path + "index.dat"
  
  Files.readAllBytes(Paths.get(fullPath))
}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_12(request: play.api.mvc.Request[AnyContent]): String = {
  val userPath = request.body.asJson.get("path").as[String]
  val baseDir = "/usr/local/share/"
  
  // ruleid: scala-filename-utils
  val normalizedPath = FilenameUtils.normalize(userPath, false) // Not using normalize correctly
  val fullPath = baseDir + normalizedPath
  
  Source.fromFile(fullPath).getLines().mkString("\n")
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_13(request: play.api.mvc.Request[AnyContent]): File = {
  val relativePath = request.getQueryString("path").getOrElse("default")
  val baseDir = "/var/log/"
  
  // ruleid: scala-filename-utils
  val path = FilenameUtils.concat(baseDir, relativePath)
  
  new File(path)
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_14(request: HttpRequest): String = {
  val userInput = request.uri.query().get("module").getOrElse("core")
  val baseDir = "/app/modules/"
  
  // ruleid: scala-filename-utils
  val dirPath = FilenameUtils.getPath(userInput)
  val fullPath = baseDir + dirPath + "/config.xml"
  
  Source.fromFile(fullPath).getLines().mkString("\n")
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_15(request: play.api.mvc.Request[AnyContent]): File = {
  val fileName = request.body.asFormUrlEncoded.get("filename").head
  val baseDir = "/tmp/"
  
  // ruleid: scala-filename-utils
  val name = FilenameUtils.getName(fileName)
  val fullPath = baseDir + name
  
  new File(fullPath)
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// True Negative Examples (Secure Code)

def good_case_1(request: play.api.mvc.Request[AnyContent]): File = {
  val userProvidedPath = request.getQueryString("file").getOrElse("default.txt")
  val baseDir = "/app/files/"
  
  // ok: scala-filename-utils
  val normalizedPath = FilenameUtils.normalize(userProvidedPath)
  if (normalizedPath == null || normalizedPath.contains("..") || normalizedPath.startsWith("/")) {
    throw new SecurityException("Invalid path")
  }
  
  new File(baseDir, normalizedPath)
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_2(request: play.api.mvc.Request[AnyContent]): String = {
  val userInput = request.body.asFormUrlEncoded.get("filepath").head
  val basePath = "/var/data/"
  
  // ok: scala-filename-utils
  val filename = FilenameUtils.getName(userInput) // Only get the filename, not the path
  val fullPath = basePath + filename
  
  // Verify the resolved path is still within the intended directory
  val resolvedPath = new File(fullPath).getCanonicalPath
  if (!resolvedPath.startsWith(new File(basePath).getCanonicalPath)) {
    throw new SecurityException("Path traversal attempt detected")
  }
  
  Source.fromFile(fullPath).getLines().mkString("\n")
}
// {/fact}

def good_case_3()(implicit request: play.api.mvc.Request[AnyContent]): Array[Byte] = {
  val path = request.headers.get("X-File-Path").getOrElse("default.txt")
  val storageDir = "/storage/documents/"
  
  // ok: scala-filename-utils
  val normalizedPath = FilenameUtils.normalize(path)
  if (normalizedPath == null) {
    throw new SecurityException("Invalid path")
  }
  
  val filename = FilenameUtils.getName(normalizedPath)
  val fullPath = storageDir + filename
  
  Files.readAllBytes(Paths.get(fullPath))
}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_4(request: HttpRequest): String = {
  val userPath = request.uri.query().get("path").getOrElse("default")
  val baseDir = "/app/resources/"
  
  // ok: scala-filename-utils
  val normalizedPath = FilenameUtils.normalize(userPath)
  if (normalizedPath == null || normalizedPath.contains("..")) {
    throw new SecurityException("Invalid path")
  }
  
  val safeFilename = FilenameUtils.getName(normalizedPath)
  val fullPath = baseDir + safeFilename
  
  Source.fromFile(fullPath).getLines().mkString("\n")
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_5(request: play.api.mvc.Request[AnyContent]): File = {
  val fileName = request.body.asJson.get("file").as[String]
  val baseDir = "/var/www/uploads/"
  
  // ok: scala-filename-utils
  val normalizedPath = FilenameUtils.normalize(fileName)
  if (normalizedPath == null) {
    throw new SecurityException("Invalid path")
  }
  
  val safeFileName = FilenameUtils.getName(normalizedPath)
  val fullPath = baseDir + safeFileName
  
  // Double-check the resolved path
  val resolvedPath = new File(fullPath).getCanonicalPath
  if (!resolvedPath.startsWith(new File(baseDir).getCanonicalPath)) {
    throw new SecurityException("Path traversal attempt detected")
  }
  
  new File(fullPath)
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_6(request: play.api.mvc.Request[AnyContent]): String = {
  val userInput = request.getQueryString("template").getOrElse("default")
  val templatesDir = "/app/templates/"
  
  // ok: scala-filename-utils
  // Whitelist approach - only allow specific template names
  val allowedTemplates = Set("user", "admin", "report", "default")
  if (!allowedTemplates.contains(userInput)) {
    throw new SecurityException("Invalid template name")
  }
  
  val filePath = templatesDir + userInput + ".tmpl"
  Source.fromFile(filePath).getLines().mkString("\n")
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_7(request: play.api.mvc.Request[AnyContent]): Unit = {
  val sourceFile = request.getQueryString("source").getOrElse("default.txt")
  val destFile = request.getQueryString("dest").getOrElse("output.txt")
  val baseDir = "/app/data/"
  
  // ok: scala-filename-utils
  val sourceNormalized = FilenameUtils.normalize(sourceFile)
  val destNormalized = FilenameUtils.normalize(destFile)
  
  if (sourceNormalized == null || destNormalized == null) {
    throw new SecurityException("Invalid path")
  }
  
  val sourceFilename = FilenameUtils.getName(sourceNormalized)
  val destFilename = FilenameUtils.getName(destNormalized)
  
  val sourcePath = baseDir + sourceFilename
  val destPath = baseDir + destFilename
  
  val source = new FileInputStream(sourcePath)
  val dest = new FileOutputStream(destPath)
  
  try {
    val buffer = new Array[Byte](1024)
    var length = 0
    while ({ length = source.read(buffer); length > 0 }) {
      dest.write(buffer, 0, length)
    }
  } finally {
    source.close()
    dest.close()
  }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_8(request: HttpRequest): File = {
  val userPath = request.uri.query().get("config").getOrElse("settings.conf")
  val configDir = "/etc/app/"
  
  // ok: scala-filename-utils
  // Use a whitelist of allowed configuration files
  val allowedConfigs = Map(
    "settings.conf" -> "settings.conf",
    "logging.conf" -> "logging.conf",
    "network.conf" -> "network.conf"
  )
  
  val configFile = allowedConfigs.getOrElse(userPath, "default.conf")
  val fullPath = configDir + configFile
  
  new File(fullPath)
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_9(request: play.api.mvc.Request[AnyContent]): String = {
  val relativePath = request.body.asFormUrlEncoded.get("path").head
  val baseDir = "/home/user/documents/"
  
  // ok: scala-filename-utils
  val normalizedPath = FilenameUtils.normalize(relativePath)
  if (normalizedPath == null) {
    throw new SecurityException("Invalid path")
  }
  
  val safeFilename = FilenameUtils.getName(normalizedPath)
  val fullPath = baseDir + safeFilename
  
  // Verify the resolved path is within the intended directory
  val resolvedPath = new File(fullPath).getCanonicalPath
  if (!resolvedPath.startsWith(new File(baseDir).getCanonicalPath)) {
    throw new SecurityException("Path traversal attempt detected")
  }
  
  Source.fromFile(fullPath).getLines().mkString("\n")
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_10(request: play.api.mvc.Request[AnyContent]): File = {
  val userInput = request.cookies.get("file_path").map(_.value).getOrElse("default.txt")
  val baseDir = "/var/app/files/"
  
  // ok: scala-filename-utils
  val normalizedPath = FilenameUtils.normalize(userInput)
  if (normalizedPath == null || normalizedPath.contains("..")) {
    throw new SecurityException("Invalid path")
  }
  
  // Only allow files with specific extensions
  val extension = FilenameUtils.getExtension(normalizedPath)
  val allowedExtensions = Set("txt", "pdf", "doc")
  if (!allowedExtensions.contains(extension)) {
    throw new SecurityException("Invalid file extension")
  }
  
  val safeFilename = FilenameUtils.getName(normalizedPath)
  val fullPath = baseDir + safeFilename
  
  new File(fullPath)
}
// {/fact}

def good_case_11(request: HttpRequest): Array[Byte] = {
  val fileName = request.uri.query().get("file").getOrElse("default.txt")
  val baseDir = "/opt/data/"
  
  // ok: scala-filename-utils
  val normalizedPath = FilenameUtils.normalize(fileName)
  if (normalizedPath == null) {
    throw new SecurityException("Invalid path")
  }
  
  // Extract just the filename without any path components
  val safeFilename = FilenameUtils.getName(normalizedPath)
  val fullPath = baseDir + safeFilename
  
  // Verify the resolved path is within the intended directory
  val resolvedPath = new File(fullPath).getCanonicalPath
  val canonicalBaseDir = new File(baseDir).getCanonicalPath
  if (!resolvedPath.startsWith(canonicalBaseDir)) {
    throw new SecurityException("Path traversal attempt detected")
  }
  
  Files.readAllBytes(Paths.get(fullPath))
}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_12(request: play.api.mvc.Request[AnyContent]): String = {
  val userPath = request.body.asJson.get("path").as[String]
  val baseDir = "/usr/local/share/"
  
  // ok: scala-filename-utils
  // Use normalize with unixSeparator=true to handle path separators correctly
  val normalizedPath = FilenameUtils.normalize(userPath, true)
  if (normalizedPath == null || normalizedPath.contains("..")) {
    throw new SecurityException("Invalid path")
  }
  
  val safeFilename = FilenameUtils.getName(normalizedPath)
  val fullPath = baseDir + safeFilename
  
  // Verify the resolved path is within the intended directory
  val resolvedPath = new File(fullPath).getCanonicalPath
  if (!resolvedPath.startsWith(new File(baseDir).getCanonicalPath)) {
    throw new SecurityException("Path traversal attempt detected")
  }
  
  Source.fromFile(fullPath).getLines().mkString("\n")
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_13(request: play.api.mvc.Request[AnyContent]): File = {
  val relativePath = request.getQueryString("path").getOrElse("default")
  val baseDir = "/var/log/"
  
  // ok: scala-filename-utils
  val normalizedPath = FilenameUtils.normalize(relativePath)
  if (normalizedPath == null || normalizedPath.contains("..")) {
    throw new SecurityException("Invalid path")
  }
  
  // Only allow specific log files
  val allowedLogs = Set("app.log", "error.log", "access.log", "default")
  val filename = FilenameUtils.getName(normalizedPath)
  
  if (!allowedLogs.contains(filename)) {
    throw new SecurityException("Access to this log file is not allowed")
  }
  
  new File(baseDir + filename)
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_14(request: HttpRequest): String = {
  val userInput = request.uri.query().get("module").getOrElse("core")
  val baseDir = "/app/modules/"
  
  // ok: scala-filename-utils
  // Use a whitelist approach for module names
  val allowedModules = Map(
    "core" -> "core",
    "admin" -> "admin",
    "user" -> "user",
    "reporting" -> "reporting"
  )
  
  val moduleName = allowedModules.getOrElse(userInput, "core")
  val fullPath = baseDir + moduleName + "/config.xml"
  
  Source.fromFile(fullPath).getLines().mkString("\n")
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_15(request: play.api.mvc.Request[AnyContent]): File = {
  val fileName = request.body.asFormUrlEncoded.get("filename").head
  val baseDir = "/tmp/"
  
  // ok: scala-filename-utils
  val normalizedPath = FilenameUtils.normalize(fileName)
  if (normalizedPath == null) {
    throw new SecurityException("Invalid path")
  }
  
  // Extract just the filename without any path components
  val safeFilename = FilenameUtils.getName(normalizedPath)
  
  // Additional validation: only allow alphanumeric filenames
  if (!safeFilename.matches("^[a-zA-Z0-9._-]+$")) {
    throw new SecurityException("Invalid filename characters")
  }
  
  val fullPath = baseDir + safeFilename
  
  // Verify the resolved path is within the intended directory
  val resolvedPath = new File(fullPath).getCanonicalPath
  if (!resolvedPath.startsWith(new File(baseDir).getCanonicalPath)) {
    throw new SecurityException("Path traversal attempt detected")
  }
  
  new File(fullPath)
}
// {/fact}