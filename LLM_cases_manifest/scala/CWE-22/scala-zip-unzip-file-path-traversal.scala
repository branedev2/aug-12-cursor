import java.io.{File, FileInputStream, FileOutputStream, InputStream}
import java.nio.file.{Files, Path, Paths, StandardCopyOption}
import java.util.zip.{ZipEntry, ZipFile, ZipInputStream}
import scala.io.Source
import scala.util.{Try, Success, Failure}
import scala.collection.JavaConverters._
import play.api.mvc._
import play.api.http._
import play.api.libs.json._
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.Multipart
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream
import org.apache.commons.io.{FileUtils, FilenameUtils}
// {fact rule=path-traversal@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(request: Request[AnyContent]): Unit = {
  val zipFilePath = request.getQueryString("zipfile").getOrElse("default.zip")
  val outputDir = new File("/tmp/extracted")
  outputDir.mkdirs()
  
  val zipFile = new ZipFile(zipFilePath)
  val entries = zipFile.entries()
  
  while (entries.hasMoreElements) {
    val entry = entries.nextElement()
    val entryPath = new File(outputDir, entry.getName)
    
    if (!entry.isDirectory) {
      val inputStream = zipFile.getInputStream(entry)
      // ruleid: scala-zip-unzip-file-path-traversal
      val outputStream = new FileOutputStream(entryPath)
      
      val buffer = new Array[Byte](1024)
      var length = inputStream.read(buffer)
      while (length > 0) {
        outputStream.write(buffer, 0, length)
        length = inputStream.read(buffer)
      }
      
      outputStream.close()
      inputStream.close()
    }
  }
  zipFile.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_2(): Unit = {
  val zipFilePath = "user_uploads/archive.zip"
  val outputDir = "/var/www/uploads"
  
  val zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath))
  var entry = zipInputStream.getNextEntry
  
  while (entry != null) {
    if (!entry.isDirectory) {
      // ruleid: scala-zip-unzip-file-path-traversal
      val outputFile = new File(outputDir, entry.getName)
      outputFile.getParentFile.mkdirs()
      
      val outputStream = new FileOutputStream(outputFile)
      val buffer = new Array[Byte](1024)
      var len = 0
      while ({len = zipInputStream.read(buffer); len} > 0) {
        outputStream.write(buffer, 0, len)
      }
      outputStream.close()
    }
    zipInputStream.closeEntry()
    entry = zipInputStream.getNextEntry
  }
  zipInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_3(request: Request[AnyContent]): Unit = {
  val zipFile = request.body.asMultipartFormData.get.file("archive").get
  val tempFile = zipFile.ref.path.toFile
  val destinationDir = new File("/opt/app/data")
  
  val zip = new ZipFile(tempFile)
  val entries = zip.entries()
  
  while (entries.hasMoreElements) {
    val entry = entries.nextElement()
    if (!entry.isDirectory) {
      val entryName = entry.getName
      // ruleid: scala-zip-unzip-file-path-traversal
      val destFile = new File(destinationDir, entryName)
      
      val in = zip.getInputStream(entry)
      val out = new FileOutputStream(destFile)
      
      val buffer = new Array[Byte](8192)
      var bytesRead = 0
      while ({bytesRead = in.read(buffer); bytesRead} != -1) {
        out.write(buffer, 0, bytesRead)
      }
      
      in.close()
      out.close()
    }
  }
  zip.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_4(request: Request[AnyContent]): Unit = {
  val zipFilePath = request.getQueryString("file").getOrElse("default.zip")
  val outputDir = Paths.get("/usr/local/share/data")
  
  val zipFile = new ZipFile(zipFilePath)
  
  for (entry <- zipFile.entries().asScala) {
    if (!entry.isDirectory) {
      // ruleid: scala-zip-unzip-file-path-traversal
      val outputPath = outputDir.resolve(entry.getName)
      Files.createDirectories(outputPath.getParent)
      
      val inputStream = zipFile.getInputStream(entry)
      Files.copy(inputStream, outputPath, StandardCopyOption.REPLACE_EXISTING)
      inputStream.close()
    }
  }
  zipFile.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_5(): Unit = {
  val zipFilePath = "/tmp/uploaded.zip"
  val extractPath = "/home/user/webapp/public"
  
  val zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath))
  var entry = zipInputStream.getNextEntry
  
  while (entry != null) {
    val fileName = entry.getName
    // ruleid: scala-zip-unzip-file-path-traversal
    val newFile = new File(extractPath + File.separator + fileName)
    
    if (entry.isDirectory) {
      newFile.mkdirs()
    } else {
      new File(newFile.getParent).mkdirs()
      val fos = new FileOutputStream(newFile)
      val buffer = new Array[Byte](1024)
      var len = 0
      while ({len = zipInputStream.read(buffer); len} > 0) {
        fos.write(buffer, 0, len)
      }
      fos.close()
    }
    zipInputStream.closeEntry()
    entry = zipInputStream.getNextEntry
  }
  zipInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_6(request: Request[AnyContent]): Unit = {
  val zipFile = request.body.asRaw.get.asFile
  val targetDir = new File("/var/data")
  
  val zipArchive = new ZipArchiveInputStream(new FileInputStream(zipFile))
  var entry = zipArchive.getNextZipEntry
  
  while (entry != null) {
    if (!entry.isDirectory) {
      // ruleid: scala-zip-unzip-file-path-traversal
      val outputFile = new File(targetDir, entry.getName)
      outputFile.getParentFile.mkdirs()
      
      val outputStream = new FileOutputStream(outputFile)
      val buffer = new Array[Byte](8192)
      var bytesRead = 0
      while ({bytesRead = zipArchive.read(buffer); bytesRead} != -1) {
        outputStream.write(buffer, 0, bytesRead)
      }
      outputStream.close()
    }
    entry = zipArchive.getNextZipEntry
  }
  zipArchive.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_7(): Unit = {
  val zipFilePath = "/tmp/backup.zip"
  val extractDir = "/etc/config"
  
  val zipFile = new ZipFile(zipFilePath)
  val entries = zipFile.entries()
  
  while (entries.hasMoreElements) {
    val entry = entries.nextElement()
    // ruleid: scala-zip-unzip-file-path-traversal
    val destPath = Paths.get(extractDir, entry.getName)
    
    if (!entry.isDirectory) {
      Files.createDirectories(destPath.getParent)
      Files.copy(zipFile.getInputStream(entry), destPath, StandardCopyOption.REPLACE_EXISTING)
    } else {
      Files.createDirectories(destPath)
    }
  }
  zipFile.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_8(request: Request[AnyContent]): Unit = {
  val zipFilePath = request.getQueryString("archive").getOrElse("default.zip")
  val outputDir = "/opt/application/files"
  
  val zipInputStream = new ZipInputStream(Files.newInputStream(Paths.get(zipFilePath)))
  var entry = zipInputStream.getNextEntry
  
  while (entry != null) {
    if (!entry.isDirectory) {
      // ruleid: scala-zip-unzip-file-path-traversal
      val outputPath = Paths.get(outputDir, entry.getName)
      Files.createDirectories(outputPath.getParent)
      
      val outputStream = Files.newOutputStream(outputPath)
      val buffer = new Array[Byte](4096)
      var bytesRead = 0
      while ({bytesRead = zipInputStream.read(buffer); bytesRead} > 0) {
        outputStream.write(buffer, 0, bytesRead)
      }
      outputStream.close()
    }
    zipInputStream.closeEntry()
    entry = zipInputStream.getNextEntry
  }
  zipInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_9(): Unit = {
  val zipFilePath = "/var/tmp/package.zip"
  val extractPath = "/usr/share/app"
  
  val zipFile = new ZipFile(zipFilePath)
  
  for (entry <- zipFile.entries().asScala) {
    // ruleid: scala-zip-unzip-file-path-traversal
    val outFile = new File(extractPath, entry.getName)
    
    if (entry.isDirectory) {
      outFile.mkdirs()
    } else {
      val in = zipFile.getInputStream(entry)
      val out = new FileOutputStream(outFile)
      
      val buffer = new Array[Byte](2048)
      var len = 0
      while ({len = in.read(buffer); len} != -1) {
        out.write(buffer, 0, len)
      }
      
      in.close()
      out.close()
    }
  }
  zipFile.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_10(request: Request[AnyContent]): Unit = {
  val zipFilePath = request.getQueryString("zipfile").getOrElse("default.zip")
  val outputDir = "/home/user/documents"
  
  val zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath))
  var zipEntry = zipInputStream.getNextEntry
  
  while (zipEntry != null) {
    val entryName = zipEntry.getName
    
    if (!zipEntry.isDirectory) {
      // ruleid: scala-zip-unzip-file-path-traversal
      val outputFile = new File(outputDir + File.separator + entryName)
      new File(outputFile.getParent).mkdirs()
      
      val outputStream = new FileOutputStream(outputFile)
      val buffer = new Array[Byte](1024)
      var length = 0
      while ({length = zipInputStream.read(buffer); length} > 0) {
        outputStream.write(buffer, 0, length)
      }
      outputStream.close()
    }
    
    zipInputStream.closeEntry()
    zipEntry = zipInputStream.getNextEntry
  }
  zipInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_11(): Unit = {
  val zipFilePath = "/tmp/data.zip"
  val targetDir = "/var/www/html"
  
  val zipFile = new ZipFile(zipFilePath)
  val entries = zipFile.entries()
  
  while (entries.hasMoreElements) {
    val entry = entries.nextElement()
    
    if (!entry.isDirectory) {
      // ruleid: scala-zip-unzip-file-path-traversal
      val destFile = Paths.get(targetDir, entry.getName)
      Files.createDirectories(destFile.getParent)
      
      val inputStream = zipFile.getInputStream(entry)
      Files.copy(inputStream, destFile, StandardCopyOption.REPLACE_EXISTING)
      inputStream.close()
    }
  }
  zipFile.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_12(request: Request[AnyContent]): Unit = {
  val zipFile = request.body.asMultipartFormData.get.file("zipfile").get.ref.path.toFile
  val destDir = new File("/opt/webapp/resources")
  
  val zipInputStream = new ZipInputStream(new FileInputStream(zipFile))
  var entry = zipInputStream.getNextEntry
  
  while (entry != null) {
    // ruleid: scala-zip-unzip-file-path-traversal
    val outputFile = new File(destDir, entry.getName)
    
    if (!entry.isDirectory) {
      outputFile.getParentFile.mkdirs()
      val outputStream = new FileOutputStream(outputFile)
      
      val buffer = new Array[Byte](1024)
      var len = 0
      while ({len = zipInputStream.read(buffer); len} > 0) {
        outputStream.write(buffer, 0, len)
      }
      outputStream.close()
    }
    
    zipInputStream.closeEntry()
    entry = zipInputStream.getNextEntry
  }
  zipInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_13(): Unit = {
  val zipFilePath = "/var/tmp/archive.zip"
  val extractPath = "/home/app/data"
  
  val zipArchiveInputStream = new ZipArchiveInputStream(new FileInputStream(zipFilePath))
  var entry = zipArchiveInputStream.getNextZipEntry
  
  while (entry != null) {
    if (!entry.isDirectory) {
      // ruleid: scala-zip-unzip-file-path-traversal
      val outputFile = new File(extractPath, entry.getName)
      outputFile.getParentFile.mkdirs()
      
      val outputStream = new FileOutputStream(outputFile)
      val buffer = new Array[Byte](8192)
      var bytesRead = 0
      while ({bytesRead = zipArchiveInputStream.read(buffer); bytesRead} != -1) {
        outputStream.write(buffer, 0, bytesRead)
      }
      outputStream.close()
    }
    entry = zipArchiveInputStream.getNextZipEntry
  }
  zipArchiveInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_14(request: Request[AnyContent]): Unit = {
  val zipFilePath = request.getQueryString("file").getOrElse("/tmp/default.zip")
  val outputDir = "/usr/local/tomcat/webapps/ROOT"
  
  val zipFile = new ZipFile(zipFilePath)
  
  for (entry <- zipFile.entries().asScala) {
    val entryName = entry.getName
    // ruleid: scala-zip-unzip-file-path-traversal
    val outputPath = Paths.get(outputDir, entryName)
    
    if (!entry.isDirectory) {
      Files.createDirectories(outputPath.getParent)
      val inputStream = zipFile.getInputStream(entry)
      Files.copy(inputStream, outputPath, StandardCopyOption.REPLACE_EXISTING)
      inputStream.close()
    } else {
      Files.createDirectories(outputPath)
    }
  }
  zipFile.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

def bad_case_15(): Unit = {
  val zipFilePath = "/tmp/updates.zip"
  val extractDir = "/etc/app/config"
  
  val zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath))
  var entry = zipInputStream.getNextEntry
  
  while (entry != null) {
    if (!entry.isDirectory) {
      // ruleid: scala-zip-unzip-file-path-traversal
      val outputFile = new File(extractDir + "/" + entry.getName)
      outputFile.getParentFile.mkdirs()
      
      val outputStream = new FileOutputStream(outputFile)
      val buffer = new Array[Byte](2048)
      var len = 0
      while ({len = zipInputStream.read(buffer); len} > 0) {
        outputStream.write(buffer, 0, len)
      }
      outputStream.close()
    }
    zipInputStream.closeEntry()
    entry = zipInputStream.getNextEntry
  }
  zipInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// True Negatives (Safe Code)

def good_case_1(request: Request[AnyContent]): Unit = {
  val zipFilePath = request.getQueryString("zipfile").getOrElse("default.zip")
  val outputDir = new File("/tmp/extracted")
  outputDir.mkdirs()
  
  val zipFile = new ZipFile(zipFilePath)
  val entries = zipFile.entries()
  
  while (entries.hasMoreElements) {
    val entry = entries.nextElement()
    val entryName = entry.getName
    
    // ok: scala-zip-unzip-file-path-traversal
    val normalizedPath = FilenameUtils.normalize(entryName)
    if (normalizedPath == null || normalizedPath.startsWith("..")) {
      // Skip this entry - it's trying to traverse directories
      continue
    }
    
    val entryPath = new File(outputDir, normalizedPath)
    if (!entryPath.getCanonicalPath.startsWith(outputDir.getCanonicalPath)) {
      // Skip this entry - it's trying to escape the target directory
      continue
    }
    
    if (!entry.isDirectory) {
      val inputStream = zipFile.getInputStream(entry)
      val outputStream = new FileOutputStream(entryPath)
      
      val buffer = new Array[Byte](1024)
      var length = inputStream.read(buffer)
      while (length > 0) {
        outputStream.write(buffer, 0, length)
        length = inputStream.read(buffer)
      }
      
      outputStream.close()
      inputStream.close()
    }
  }
  zipFile.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_2(): Unit = {
  val zipFilePath = "user_uploads/archive.zip"
  val outputDir = new File("/var/www/uploads")
  val canonicalOutputDirPath = outputDir.getCanonicalPath
  
  val zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath))
  var entry = zipInputStream.getNextEntry
  
  while (entry != null) {
    if (!entry.isDirectory) {
      // ok: scala-zip-unzip-file-path-traversal
      val outputFile = new File(outputDir, entry.getName)
      val canonicalDestinationPath = outputFile.getCanonicalPath
      
      if (!canonicalDestinationPath.startsWith(canonicalOutputDirPath + File.separator)) {
        // Path traversal attempt detected, skip this entry
        zipInputStream.closeEntry()
        entry = zipInputStream.getNextEntry
        continue
      }
      
      outputFile.getParentFile.mkdirs()
      val outputStream = new FileOutputStream(outputFile)
      val buffer = new Array[Byte](1024)
      var len = 0
      while ({len = zipInputStream.read(buffer); len} > 0) {
        outputStream.write(buffer, 0, len)
      }
      outputStream.close()
    }
    zipInputStream.closeEntry()
    entry = zipInputStream.getNextEntry
  }
  zipInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_3(request: Request[AnyContent]): Unit = {
  val zipFile = request.body.asMultipartFormData.get.file("archive").get
  val tempFile = zipFile.ref.path.toFile
  val destinationDir = new File("/opt/app/data")
  val canonicalDestDir = destinationDir.getCanonicalPath
  
  val zip = new ZipFile(tempFile)
  val entries = zip.entries()
  
  while (entries.hasMoreElements) {
    val entry = entries.nextElement()
    if (!entry.isDirectory) {
      val entryName = entry.getName
      
      // ok: scala-zip-unzip-file-path-traversal
      // Validate the entry name to prevent path traversal
      if (entryName.contains("..") || entryName.startsWith("/")) {
        // Skip this potentially malicious entry
        continue
      }
      
      val destFile = new File(destinationDir, entryName)
      if (!destFile.getCanonicalPath.startsWith(canonicalDestDir)) {
        // Path traversal attempt detected, skip this entry
        continue
      }
      
      destFile.getParentFile.mkdirs()
      val in = zip.getInputStream(entry)
      val out = new FileOutputStream(destFile)
      
      val buffer = new Array[Byte](8192)
      var bytesRead = 0
      while ({bytesRead = in.read(buffer); bytesRead} != -1) {
        out.write(buffer, 0, bytesRead)
      }
      
      in.close()
      out.close()
    }
  }
  zip.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_4(request: Request[AnyContent]): Unit = {
  val zipFilePath = request.getQueryString("file").getOrElse("default.zip")
  val outputDir = Paths.get("/usr/local/share/data")
  val canonicalOutputDir = outputDir.toFile.getCanonicalPath
  
  val zipFile = new ZipFile(zipFilePath)
  
  for (entry <- zipFile.entries().asScala) {
    if (!entry.isDirectory) {
      val entryName = entry.getName
      
      // ok: scala-zip-unzip-file-path-traversal
      // Sanitize the entry name to prevent path traversal
      val sanitizedName = entryName.replaceAll("\\.\\.", "").replaceAll("^/", "")
      val outputPath = outputDir.resolve(sanitizedName)
      
      // Double-check that we're still in the target directory
      if (!outputPath.toFile.getCanonicalPath.startsWith(canonicalOutputDir)) {
        // Path traversal attempt detected, skip this entry
        continue
      }
      
      Files.createDirectories(outputPath.getParent)
      val inputStream = zipFile.getInputStream(entry)
      Files.copy(inputStream, outputPath, StandardCopyOption.REPLACE_EXISTING)
      inputStream.close()
    }
  }
  zipFile.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_5(): Unit = {
  val zipFilePath = "/tmp/uploaded.zip"
  val extractPath = "/home/user/webapp/public"
  val safeExtractPath = new File(extractPath).getCanonicalPath
  
  val zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath))
  var entry = zipInputStream.getNextEntry
  
  while (entry != null) {
    val fileName = entry.getName
    
    // ok: scala-zip-unzip-file-path-traversal
    // Validate zip entry path
    if (fileName.contains("..") || fileName.startsWith("/")) {
      // Skip potentially malicious entries
      zipInputStream.closeEntry()
      entry = zipInputStream.getNextEntry
      continue
    }
    
    val newFile = new File(extractPath, fileName)
    val canonicalPath = newFile.getCanonicalPath
    
    // Ensure the file will be written inside the target directory
    if (!canonicalPath.startsWith(safeExtractPath)) {
      // Path traversal attempt detected, skip this entry
      zipInputStream.closeEntry()
      entry = zipInputStream.getNextEntry
      continue
    }
    
    if (entry.isDirectory) {
      newFile.mkdirs()
    } else {
      new File(newFile.getParent).mkdirs()
      val fos = new FileOutputStream(newFile)
      val buffer = new Array[Byte](1024)
      var len = 0
      while ({len = zipInputStream.read(buffer); len} > 0) {
        fos.write(buffer, 0, len)
      }
      fos.close()
    }
    zipInputStream.closeEntry()
    entry = zipInputStream.getNextEntry
  }
  zipInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_6(request: Request[AnyContent]): Unit = {
  val zipFile = request.body.asRaw.get.asFile
  val targetDir = new File("/var/data")
  val canonicalTargetDir = targetDir.getCanonicalPath
  
  val zipArchive = new ZipArchiveInputStream(new FileInputStream(zipFile))
  var entry = zipArchive.getNextZipEntry
  
  while (entry != null) {
    if (!entry.isDirectory) {
      val entryName = entry.getName
      
      // ok: scala-zip-unzip-file-path-traversal
      // Check for path traversal attempts
      if (entryName.contains("..") || entryName.startsWith("/")) {
        // Skip this entry
        entry = zipArchive.getNextZipEntry
        continue
      }
      
      val outputFile = new File(targetDir, entryName)
      
      // Verify the final path is within the target directory
      if (!outputFile.getCanonicalPath.startsWith(canonicalTargetDir)) {
        // Path traversal attempt detected, skip this entry
        entry = zipArchive.getNextZipEntry
        continue
      }
      
      outputFile.getParentFile.mkdirs()
      val outputStream = new FileOutputStream(outputFile)
      val buffer = new Array[Byte](8192)
      var bytesRead = 0
      while ({bytesRead = zipArchive.read(buffer); bytesRead} != -1) {
        outputStream.write(buffer, 0, bytesRead)
      }
      outputStream.close()
    }
    entry = zipArchive.getNextZipEntry
  }
  zipArchive.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_7(): Unit = {
  val zipFilePath = "/tmp/backup.zip"
  val extractDir = new File("/etc/config")
  val canonicalExtractDir = extractDir.getCanonicalPath
  
  val zipFile = new ZipFile(zipFilePath)
  val entries = zipFile.entries()
  
  while (entries.hasMoreElements) {
    val entry = entries.nextElement()
    val entryName = entry.getName
    
    // ok: scala-zip-unzip-file-path-traversal
    // Validate the entry name
    if (entryName.contains("..") || entryName.startsWith("/")) {
      // Skip this entry - potential path traversal
      continue
    }
    
    val destPath = new File(extractDir, entryName)
    
    // Ensure the destination is within the extract directory
    if (!destPath.getCanonicalPath.startsWith(canonicalExtractDir)) {
      // Skip this entry - it's trying to write outside the target directory
      continue
    }
    
    if (!entry.isDirectory) {
      destPath.getParentFile.mkdirs()
      val inputStream = zipFile.getInputStream(entry)
      val outputStream = new FileOutputStream(destPath)
      
      val buffer = new Array[Byte](4096)
      var bytesRead = 0
      while ({bytesRead = inputStream.read(buffer); bytesRead} > 0) {
        outputStream.write(buffer, 0, bytesRead)
      }
      
      inputStream.close()
      outputStream.close()
    } else {
      destPath.mkdirs()
    }
  }
  zipFile.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_8(request: Request[AnyContent]): Unit = {
  val zipFilePath = request.getQueryString("archive").getOrElse("default.zip")
  val outputDir = new File("/opt/application/files")
  val canonicalOutputDir = outputDir.getCanonicalPath
  
  val zipInputStream = new ZipInputStream(Files.newInputStream(Paths.get(zipFilePath)))
  var entry = zipInputStream.getNextEntry
  
  while (entry != null) {
    if (!entry.isDirectory) {
      val entryName = entry.getName
      
      // ok: scala-zip-unzip-file-path-traversal
      // Validate and sanitize the entry name
      val sanitizedName = FilenameUtils.normalize(entryName)
      if (sanitizedName == null || sanitizedName.contains("..") || sanitizedName.startsWith("/")) {
        // Skip this entry - potential path traversal
        zipInputStream.closeEntry()
        entry = zipInputStream.getNextEntry
        continue
      }
      
      val outputFile = new File(outputDir, sanitizedName)
      
      // Verify the final path is within the target directory
      if (!outputFile.getCanonicalPath.startsWith(canonicalOutputDir)) {
        // Path traversal attempt detected, skip this entry
        zipInputStream.closeEntry()
        entry = zipInputStream.getNextEntry
        continue
      }
      
      outputFile.getParentFile.mkdirs()
      val outputStream = new FileOutputStream(outputFile)
      val buffer = new Array[Byte](4096)
      var bytesRead = 0
      while ({bytesRead = zipInputStream.read(buffer); bytesRead} > 0) {
        outputStream.write(buffer, 0, bytesRead)
      }
      outputStream.close()
    }
    zipInputStream.closeEntry()
    entry = zipInputStream.getNextEntry
  }
  zipInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_9(): Unit = {
  val zipFilePath = "/var/tmp/package.zip"
  val extractPath = new File("/usr/share/app")
  val canonicalExtractPath = extractPath.getCanonicalPath
  
  val zipFile = new ZipFile(zipFilePath)
  
  for (entry <- zipFile.entries().asScala) {
    val entryName = entry.getName
    
    // ok: scala-zip-unzip-file-path-traversal
    // Check for path traversal attempts
    if (entryName.contains("..") || entryName.startsWith("/")) {
      // Skip this entry
      continue
    }
    
    val outFile = new File(extractPath, entryName)
    
    // Verify the final path is within the target directory
    if (!outFile.getCanonicalPath.startsWith(canonicalExtractPath)) {
      // Path traversal attempt detected, skip this entry
      continue
    }
    
    if (entry.isDirectory) {
      outFile.mkdirs()
    } else {
      outFile.getParentFile.mkdirs()
      val in = zipFile.getInputStream(entry)
      val out = new FileOutputStream(outFile)
      
      val buffer = new Array[Byte](2048)
      var len = 0
      while ({len = in.read(buffer); len} != -1) {
        out.write(buffer, 0, len)
      }
      
      in.close()
      out.close()
    }
  }
  zipFile.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_10(request: Request[AnyContent]): Unit = {
  val zipFilePath = request.getQueryString("zipfile").getOrElse("default.zip")
  val outputDir = new File("/home/user/documents")
  val canonicalOutputDir = outputDir.getCanonicalPath
  
  val zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath))
  var zipEntry = zipInputStream.getNextEntry
  
  while (zipEntry != null) {
    val entryName = zipEntry.getName
    
    // ok: scala-zip-unzip-file-path-traversal
    // Validate the entry name
    if (entryName.contains("..") || entryName.startsWith("/")) {
      // Skip this entry - potential path traversal
      zipInputStream.closeEntry()
      zipEntry = zipInputStream.getNextEntry
      continue
    }
    
    val outputFile = new File(outputDir, entryName)
    
    // Verify the final path is within the target directory
    if (!outputFile.getCanonicalPath.startsWith(canonicalOutputDir)) {
      // Path traversal attempt detected, skip this entry
      zipInputStream.closeEntry()
      zipEntry = zipInputStream.getNextEntry
      continue
    }
    
    if (!zipEntry.isDirectory) {
      outputFile.getParentFile.mkdirs()
      val outputStream = new FileOutputStream(outputFile)
      val buffer = new Array[Byte](1024)
      var length = 0
      while ({length = zipInputStream.read(buffer); length} > 0) {
        outputStream.write(buffer, 0, length)
      }
      outputStream.close()
    }
    
    zipInputStream.closeEntry()
    zipEntry = zipInputStream.getNextEntry
  }
  zipInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_11(): Unit = {
  val zipFilePath = "/tmp/data.zip"
  val targetDir = Paths.get("/var/www/html")
  val canonicalTargetDir = targetDir.toFile.getCanonicalPath
  
  val zipFile = new ZipFile(zipFilePath)
  val entries = zipFile.entries()
  
  while (entries.hasMoreElements) {
    val entry = entries.nextElement()
    val entryName = entry.getName
    
    // ok: scala-zip-unzip-file-path-traversal
    // Validate the entry name
    if (entryName.contains("..") || entryName.startsWith("/")) {
      // Skip this entry - potential path traversal
      continue
    }
    
    val destFile = targetDir.resolve(entryName)
    
    // Ensure the destination is within the target directory
    if (!destFile.toFile.getCanonicalPath.startsWith(canonicalTargetDir)) {
      // Skip this entry - it's trying to write outside the target directory
      continue
    }
    
    if (!entry.isDirectory) {
      Files.createDirectories(destFile.getParent)
      val inputStream = zipFile.getInputStream(entry)
      Files.copy(inputStream, destFile, StandardCopyOption.REPLACE_EXISTING)
      inputStream.close()
    } else {
      Files.createDirectories(destFile)
    }
  }
  zipFile.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_12(request: Request[AnyContent]): Unit = {
  val zipFile = request.body.asMultipartFormData.get.file("zipfile").get.ref.path.toFile
  val destDir = new File("/opt/webapp/resources")
  val canonicalDestDir = destDir.getCanonicalPath
  
  val zipInputStream = new ZipInputStream(new FileInputStream(zipFile))
  var entry = zipInputStream.getNextEntry
  
  while (entry != null) {
    val entryName = entry.getName
    
    // ok: scala-zip-unzip-file-path-traversal
    // Validate zip entry path
    val normalizedPath = FilenameUtils.normalize(entryName)
    if (normalizedPath == null || normalizedPath.contains("..") || normalizedPath.startsWith("/")) {
      // Skip this entry - potential path traversal
      zipInputStream.closeEntry()
      entry = zipInputStream.getNextEntry
      continue
    }
    
    val outputFile = new File(destDir, normalizedPath)
    
    // Verify the final path is within the target directory
    if (!outputFile.getCanonicalPath.startsWith(canonicalDestDir)) {
      // Path traversal attempt detected, skip this entry
      zipInputStream.closeEntry()
      entry = zipInputStream.getNextEntry
      continue
    }
    
    if (!entry.isDirectory) {
      outputFile.getParentFile.mkdirs()
      val outputStream = new FileOutputStream(outputFile)
      
      val buffer = new Array[Byte](1024)
      var len = 0
      while ({len = zipInputStream.read(buffer); len} > 0) {
        outputStream.write(buffer, 0, len)
      }
      outputStream.close()
    }
    
    zipInputStream.closeEntry()
    entry = zipInputStream.getNextEntry
  }
  zipInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_13(): Unit = {
  val zipFilePath = "/var/tmp/archive.zip"
  val extractPath = new File("/home/app/data")
  val canonicalExtractPath = extractPath.getCanonicalPath
  
  val zipArchiveInputStream = new ZipArchiveInputStream(new FileInputStream(zipFilePath))
  var entry = zipArchiveInputStream.getNextZipEntry
  
  while (entry != null) {
    if (!entry.isDirectory) {
      val entryName = entry.getName
      
      // ok: scala-zip-unzip-file-path-traversal
      // Check for path traversal attempts
      if (entryName.contains("..") || entryName.startsWith("/")) {
        // Skip this entry
        entry = zipArchiveInputStream.getNextZipEntry
        continue
      }
      
      val outputFile = new File(extractPath, entryName)
      
      // Verify the final path is within the target directory
      if (!outputFile.getCanonicalPath.startsWith(canonicalExtractPath)) {
        // Path traversal attempt detected, skip this entry
        entry = zipArchiveInputStream.getNextZipEntry
        continue
      }
      
      outputFile.getParentFile.mkdirs()
      val outputStream = new FileOutputStream(outputFile)
      val buffer = new Array[Byte](8192)
      var bytesRead = 0
      while ({bytesRead = zipArchiveInputStream.read(buffer); bytesRead} != -1) {
        outputStream.write(buffer, 0, bytesRead)
      }
      outputStream.close()
    }
    entry = zipArchiveInputStream.getNextZipEntry
  }
  zipArchiveInputStream.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_14(request: Request[AnyContent]): Unit = {
  val zipFilePath = request.getQueryString("file").getOrElse("/tmp/default.zip")
  val outputDir = new File("/usr/local/tomcat/webapps/ROOT")
  val canonicalOutputDir = outputDir.getCanonicalPath
  
  val zipFile = new ZipFile(zipFilePath)
  
  for (entry <- zipFile.entries().asScala) {
    val entryName = entry.getName
    
    // ok: scala-zip-unzip-file-path-traversal
    // Validate the entry name
    val normalizedPath = FilenameUtils.normalize(entryName, true)
    if (normalizedPath == null || normalizedPath.contains("..")) {
      // Skip this entry - potential path traversal
      continue
    }
    
    val outputFile = new File(outputDir, normalizedPath)
    
    // Verify the final path is within the target directory
    if (!outputFile.getCanonicalPath.startsWith(canonicalOutputDir)) {
      // Path traversal attempt detected, skip this entry
      continue
    }
    
    if (!entry.isDirectory) {
      outputFile.getParentFile.mkdirs()
      val inputStream = zipFile.getInputStream(entry)
      val outputStream = new FileOutputStream(outputFile)
      
      val buffer = new Array[Byte](4096)
      var bytesRead = 0
      while ({bytesRead = inputStream.read(buffer); bytesRead} > 0) {
        outputStream.write(buffer, 0, bytesRead)
      }
      
      inputStream.close()
      outputStream.close()
    } else {
      outputFile.mkdirs()
    }
  }
  zipFile.close()
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

def good_case_15(): Unit = {
  val zipFilePath = "/tmp/updates.zip"
  val extractDir = new File("/etc/app/config")
  val canonicalExtractDir = extractDir.getCanonicalPath
  
  val zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath))
  var entry = zipInputStream.getNextEntry
  
  while (entry != null) {
    if (!entry.isDirectory) {
      val entryName = entry.getName
      
      // ok: scala-zip-unzip-file-path-traversal
      // Use a utility method to safely resolve the path
      def isValidPath(path: String): Boolean = {
        val normalized = FilenameUtils.normalize(path)
        normalized != null && !normalized.contains("..") && !normalized.startsWith("/")
      }
      
      if (!isValidPath(entryName)) {
        // Skip this entry - potential path traversal
        zipInputStream.closeEntry()
        entry = zipInputStream.getNextEntry
        continue
      }
      
      val outputFile = new File(extractDir, entryName)
      
      // Verify the final path is within the target directory
      if (!outputFile.getCanonicalPath.startsWith(canonicalExtractDir)) {
        // Path traversal attempt detected, skip this entry
        zipInputStream.closeEntry()
        entry = zipInputStream.getNextEntry
        continue
      }
      
      outputFile.getParentFile.mkdirs()
      val outputStream = new FileOutputStream(outputFile)
      val buffer = new Array[Byte](2048)
      var len = 0
      while ({len = zipInputStream.read(buffer); len} > 0) {
        outputStream.write(buffer, 0, len)
      }
      outputStream.close()
    }
    zipInputStream.closeEntry()
    entry = zipInputStream.getNextEntry
  }
  zipInputStream.close()
}
// {/fact}