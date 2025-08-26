import java.nio.file.{Files, Path, Paths, StandardOpenOption}
import java.nio.file.attribute.{FileAttribute, PosixFilePermission, PosixFilePermissions}
import java.util.{HashSet, Set => JSet}
import scala.collection.JavaConverters._
import java.io.File

object FilePermissionExamples {

  // True Positive Examples (Vulnerable Code)

  def bad_case_1(): Unit = {
    val path = Paths.get("/tmp/sensitive_data.txt")
    val content = "This is sensitive data"
    Files.write(path, content.getBytes())
    
    // ruleid: scala-overly-permissive-file-permission-obj
    val permissions = PosixFilePermissions.fromString("rw-rw-rw-") // Everyone can read and write
    Files.setPosixFilePermissions(path, permissions)
  }

  def bad_case_2(): Unit = {
    val file = new File("/tmp/config_file.ini")
    file.createNewFile()
    
    // ruleid: scala-overly-permissive-file-permission-obj
    val result = file.setReadable(true, false) // Readable by everyone
    val result2 = file.setWritable(true, false) // Writable by everyone
  }

  def bad_case_3(): Unit = {
    val path = Paths.get("/tmp/executable_script.sh")
    val content = "#!/bin/bash\necho 'Hello World'"
    Files.write(path, content.getBytes())
    
    // ruleid: scala-overly-permissive-file-permission-obj
    val permissions = new HashSet[PosixFilePermission]()
    permissions.add(PosixFilePermission.OWNER_READ)
    permissions.add(PosixFilePermission.OWNER_WRITE)
    permissions.add(PosixFilePermission.OWNER_EXECUTE)
    permissions.add(PosixFilePermission.GROUP_READ)
    permissions.add(PosixFilePermission.GROUP_WRITE) // Group write permission
    permissions.add(PosixFilePermission.OTHERS_READ)
    permissions.add(PosixFilePermission.OTHERS_EXECUTE) // Others execute permission
    Files.setPosixFilePermissions(path, permissions)
  }

  def bad_case_4(): Unit = {
    val path = Paths.get("/var/app/data.db")
    
    // ruleid: scala-overly-permissive-file-permission-obj
    val perms = PosixFilePermissions.asFileAttribute(
      PosixFilePermissions.fromString("rwxrwxr-x") // Group write and execute permissions
    )
    Files.createFile(path, perms)
  }

  def bad_case_5(): Unit = {
    val dir = Paths.get("/opt/app/uploads")
    
    // ruleid: scala-overly-permissive-file-permission-obj
    val permissions = PosixFilePermissions.fromString("rwxrwxrwx") // Full permissions for everyone
    Files.createDirectories(dir)
    Files.setPosixFilePermissions(dir, permissions)
  }

  def bad_case_6(): Unit = {
    val file = new File("/etc/app/settings.conf")
    file.createNewFile()
    
    // ruleid: scala-overly-permissive-file-permission-obj
    file.setExecutable(true, false) // Executable by everyone
  }

  def bad_case_7(): Unit = {
    val path = Paths.get("/home/user/app/logs.txt")
    Files.createFile(path)
    
    // ruleid: scala-overly-permissive-file-permission-obj
    val perms = new HashSet[PosixFilePermission]()
    perms.add(PosixFilePermission.OWNER_READ)
    perms.add(PosixFilePermission.OWNER_WRITE)
    perms.add(PosixFilePermission.GROUP_READ)
    perms.add(PosixFilePermission.GROUP_WRITE)
    perms.add(PosixFilePermission.OTHERS_WRITE) // Others write permission
    Files.setPosixFilePermissions(path, perms)
  }

  def bad_case_8(): Unit = {
    val tempDir = Paths.get(System.getProperty("java.io.tmpdir"), "app_data")
    Files.createDirectories(tempDir)
    
    // ruleid: scala-overly-permissive-file-permission-obj
    val permissions = PosixFilePermissions.fromString("rwxr-xrwx") // Others has read, write, execute
    Files.setPosixFilePermissions(tempDir, permissions)
  }

  def bad_case_9(): Unit = {
    val configFile = Paths.get("/etc/myapp/config.json")
    val content = """{"api_key": "secret_key"}"""
    Files.write(configFile, content.getBytes())
    
    // ruleid: scala-overly-permissive-file-permission-obj
    val permSet = new HashSet[PosixFilePermission]()
    permSet.add(PosixFilePermission.OWNER_READ)
    permSet.add(PosixFilePermission.OWNER_WRITE)
    permSet.add(PosixFilePermission.GROUP_READ)
    permSet.add(PosixFilePermission.GROUP_EXECUTE) // Group execute permission
    permSet.add(PosixFilePermission.OTHERS_READ)
    Files.setPosixFilePermissions(configFile, permSet)
  }

  def bad_case_10(): Unit = {
    val keyFile = new File("/home/user/.ssh/custom_key")
    keyFile.createNewFile()
    
    // ruleid: scala-overly-permissive-file-permission-obj
    keyFile.setReadable(true, false) // Readable by everyone
  }

  def bad_case_11(): Unit = {
    val path = Paths.get("/var/www/html/uploads")
    Files.createDirectories(path)
    
    // ruleid: scala-overly-permissive-file-permission-obj
    val perms: FileAttribute[JSet[PosixFilePermission]] = PosixFilePermissions.asFileAttribute(
      PosixFilePermissions.fromString("rwxrwxrwx") // Full permissions for everyone
    )
    val newFile = Files.createFile(path.resolve("index.html"), perms)
  }

  def bad_case_12(): Unit = {
    val dbFile = Paths.get("/opt/data/users.db")
    
    // ruleid: scala-overly-permissive-file-permission-obj
    val permissions = PosixFilePermissions.fromString("rw-rw-r--") // Group write permission
    Files.createFile(dbFile)
    Files.setPosixFilePermissions(dbFile, permissions)
  }

  def bad_case_13(): Unit = {
    val scriptPath = Paths.get("/usr/local/bin/custom_script.sh")
    val scriptContent = "#!/bin/bash\necho 'Running custom script'"
    Files.write(scriptPath, scriptContent.getBytes())
    
    // ruleid: scala-overly-permissive-file-permission-obj
    val permSet = new HashSet[PosixFilePermission]()
    permSet.add(PosixFilePermission.OWNER_READ)
    permSet.add(PosixFilePermission.OWNER_WRITE)
    permSet.add(PosixFilePermission.OWNER_EXECUTE)
    permSet.add(PosixFilePermission.GROUP_READ)
    permSet.add(PosixFilePermission.GROUP_WRITE) // Group write permission
    permSet.add(PosixFilePermission.GROUP_EXECUTE) // Group execute permission
    permSet.add(PosixFilePermission.OTHERS_READ)
    permSet.add(PosixFilePermission.OTHERS_EXECUTE) // Others execute permission
    Files.setPosixFilePermissions(scriptPath, permSet)
  }

  def bad_case_14(): Unit = {
    val file = new File("/var/app/credentials.txt")
    file.createNewFile()
    
    // ruleid: scala-overly-permissive-file-permission-obj
    file.setWritable(true, false) // Writable by everyone
    file.setReadable(true, false) // Readable by everyone
  }

  def bad_case_15(): Unit = {
    val logDir = Paths.get("/var/log/myapp")
    Files.createDirectories(logDir)
    val logFile = logDir.resolve("app.log")
    Files.createFile(logFile)
    
    // ruleid: scala-overly-permissive-file-permission-obj
    val permissions = PosixFilePermissions.fromString("rw-rw-rw-") // Everyone can read and write
    Files.setPosixFilePermissions(logFile, permissions)
  }

  // True Negative Examples (Secure Code)

  def good_case_1(): Unit = {
    val path = Paths.get("/tmp/sensitive_data.txt")
    val content = "This is sensitive data"
    Files.write(path, content.getBytes())
    
    // ok: scala-overly-permissive-file-permission-obj
    val permissions = PosixFilePermissions.fromString("rw-------") // Only owner can read and write
    Files.setPosixFilePermissions(path, permissions)
  }

  def good_case_2(): Unit = {
    val file = new File("/tmp/config_file.ini")
    file.createNewFile()
    
    // ok: scala-overly-permissive-file-permission-obj
    val result = file.setReadable(true, true) // Readable only by owner
    val result2 = file.setWritable(true, true) // Writable only by owner
  }

  def good_case_3(): Unit = {
    val path = Paths.get("/tmp/executable_script.sh")
    val content = "#!/bin/bash\necho 'Hello World'"
    Files.write(path, content.getBytes())
    
    // ok: scala-overly-permissive-file-permission-obj
    val permissions = new HashSet[PosixFilePermission]()
    permissions.add(PosixFilePermission.OWNER_READ)
    permissions.add(PosixFilePermission.OWNER_WRITE)
    permissions.add(PosixFilePermission.OWNER_EXECUTE)
    permissions.add(PosixFilePermission.GROUP_READ)
    permissions.add(PosixFilePermission.OTHERS_READ)
    Files.setPosixFilePermissions(path, permissions)
  }

  def good_case_4(): Unit = {
    val path = Paths.get("/var/app/data.db")
    
    // ok: scala-overly-permissive-file-permission-obj
    val perms = PosixFilePermissions.asFileAttribute(
      PosixFilePermissions.fromString("rw-r-----") // Only owner can write, group can read
    )
    Files.createFile(path, perms)
  }

  def good_case_5(): Unit = {
    val dir = Paths.get("/opt/app/uploads")
    
    // ok: scala-overly-permissive-file-permission-obj
    val permissions = PosixFilePermissions.fromString("rwxr-x---") // Owner full access, group can read and execute
    Files.createDirectories(dir)
    Files.setPosixFilePermissions(dir, permissions)
  }

  def good_case_6(): Unit = {
    val file = new File("/etc/app/settings.conf")
    file.createNewFile()
    
    // ok: scala-overly-permissive-file-permission-obj
    file.setExecutable(true, true) // Executable only by owner
  }

  def good_case_7(): Unit = {
    val path = Paths.get("/home/user/app/logs.txt")
    Files.createFile(path)
    
    // ok: scala-overly-permissive-file-permission-obj
    val perms = new HashSet[PosixFilePermission]()
    perms.add(PosixFilePermission.OWNER_READ)
    perms.add(PosixFilePermission.OWNER_WRITE)
    perms.add(PosixFilePermission.GROUP_READ)
    Files.setPosixFilePermissions(path, perms)
  }

  def good_case_8(): Unit = {
    val tempDir = Paths.get(System.getProperty("java.io.tmpdir"), "app_data")
    Files.createDirectories(tempDir)
    
    // ok: scala-overly-permissive-file-permission-obj
    val permissions = PosixFilePermissions.fromString("rwxr-x---") // Owner full access, group can read and execute
    Files.setPosixFilePermissions(tempDir, permissions)
  }

  def good_case_9(): Unit = {
    val configFile = Paths.get("/etc/myapp/config.json")
    val content = """{"api_key": "secret_key"}"""
    Files.write(configFile, content.getBytes())
    
    // ok: scala-overly-permissive-file-permission-obj
    val permSet = new HashSet[PosixFilePermission]()
    permSet.add(PosixFilePermission.OWNER_READ)
    permSet.add(PosixFilePermission.OWNER_WRITE)
    Files.setPosixFilePermissions(configFile, permSet)
  }

  def good_case_10(): Unit = {
    val keyFile = new File("/home/user/.ssh/custom_key")
    keyFile.createNewFile()
    
    // ok: scala-overly-permissive-file-permission-obj
    keyFile.setReadable(false, false) // Not readable by anyone initially
    keyFile.setReadable(true, true) // Then make readable only by owner
  }

  def good_case_11(): Unit = {
    val path = Paths.get("/var/www/html/uploads")
    Files.createDirectories(path)
    
    // ok: scala-overly-permissive-file-permission-obj
    val perms: FileAttribute[JSet[PosixFilePermission]] = PosixFilePermissions.asFileAttribute(
      PosixFilePermissions.fromString("rw-r-----") // Owner can read/write, group can read
    )
    val newFile = Files.createFile(path.resolve("index.html"), perms)
  }

  def good_case_12(): Unit = {
    val dbFile = Paths.get("/opt/data/users.db")
    
    // ok: scala-overly-permissive-file-permission-obj
    val permissions = PosixFilePermissions.fromString("rw-------") // Only owner can read and write
    Files.createFile(dbFile)
    Files.setPosixFilePermissions(dbFile, permissions)
  }

  def good_case_13(): Unit = {
    val scriptPath = Paths.get("/usr/local/bin/custom_script.sh")
    val scriptContent = "#!/bin/bash\necho 'Running custom script'"
    Files.write(scriptPath, scriptContent.getBytes())
    
    // ok: scala-overly-permissive-file-permission-obj
    val permSet = new HashSet[PosixFilePermission]()
    permSet.add(PosixFilePermission.OWNER_READ)
    permSet.add(PosixFilePermission.OWNER_WRITE)
    permSet.add(PosixFilePermission.OWNER_EXECUTE)
    permSet.add(PosixFilePermission.GROUP_READ)
    permSet.add(PosixFilePermission.OTHERS_READ)
    Files.setPosixFilePermissions(scriptPath, permSet)
  }

  def good_case_14(): Unit = {
    val file = new File("/var/app/credentials.txt")
    file.createNewFile()
    
    // ok: scala-overly-permissive-file-permission-obj
    file.setWritable(false, false) // Remove write permission for everyone
    file.setWritable(true, true) // Add write permission only for owner
    file.setReadable(false, false) // Remove read permission for everyone
    file.setReadable(true, true) // Add read permission only for owner
  }

  def good_case_15(): Unit = {
    val logDir = Paths.get("/var/log/myapp")
    Files.createDirectories(logDir)
    val logFile = logDir.resolve("app.log")
    Files.createFile(logFile)
    
    // ok: scala-overly-permissive-file-permission-obj
    val permissions = PosixFilePermissions.fromString("rw-r-----") // Owner can read/write, group can read
    Files.setPosixFilePermissions(logFile, permissions)
  }
}