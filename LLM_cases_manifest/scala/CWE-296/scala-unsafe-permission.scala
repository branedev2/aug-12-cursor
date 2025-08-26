import java.io.FilePermission
import java.lang.reflect.ReflectPermission
import java.net.NetPermission
import java.net.SocketPermission
import java.security.{AccessController, AllPermission, Permission, PrivilegedAction}
import java.util.PropertyPermission
import scala.io.Source
import scala.util.Try
import java.security.SecurityPermission
import java.security.Policy
import java.security.ProtectionDomain
import java.security.CodeSource
import java.security.cert.Certificate
import java.security.AccessControlContext
import java.security.AccessControlException

object UnsafePermissionExamples {

  // True Positive Examples (Vulnerable Code)

  def bad_case_1(): Unit = {
    val sm = System.getSecurityManager
    if (sm != null) {
      // ruleid: scala-unsafe-permission
      sm.checkPermission(new AllPermission())
    }
    println("Proceeding with operation after granting all permissions")
  }

  def bad_case_2(): Unit = {
    try {
      // ruleid: scala-unsafe-permission
      System.setSecurityManager(null)
      println("Security manager disabled")
    } catch {
      case e: SecurityException => println("Cannot disable security manager")
    }
  }

  def bad_case_3(): Unit = {
    val securityManager = new SecurityManager() {
      override def checkPermission(perm: Permission): Unit = {
        // ruleid: scala-unsafe-permission
        // Allowing all permissions without any checks
      }
    }
    System.setSecurityManager(securityManager)
    println("Set custom security manager that grants all permissions")
  }

  def bad_case_4(): Unit = {
    val action = new PrivilegedAction[String] {
      override def run(): String = {
        // ruleid: scala-unsafe-permission
        AccessController.doPrivileged(new PrivilegedAction[Unit] {
          override def run(): Unit = {
            System.setProperty("java.security.policy", "file:/path/to/all.policy")
            Policy.getPolicy.refresh()
          }
        })
        "Privileged action completed"
      }
    }
    AccessController.doPrivileged(action)
  }

  def bad_case_5(): Unit = {
    val customSecurityManager = new SecurityManager() {
      override def checkPermission(perm: Permission): Unit = {
        if (perm.getName.contains("exitVM")) {
          super.checkPermission(perm)
        }
        // ruleid: scala-unsafe-permission
        // All other permissions are implicitly granted
      }
    }
    System.setSecurityManager(customSecurityManager)
  }

  def bad_case_6(): Unit = {
    class CustomPolicy extends Policy {
      override def getPermissions(domain: ProtectionDomain): java.security.PermissionCollection = {
        val permissions = new java.security.Permissions()
        // ruleid: scala-unsafe-permission
        permissions.add(new AllPermission())
        permissions
      }
    }
    Policy.setPolicy(new CustomPolicy())
    Policy.getPolicy.refresh()
  }

  def bad_case_7(): Unit = {
    val sm = System.getSecurityManager
    if (sm != null) {
      try {
        // ruleid: scala-unsafe-permission
        sm.checkPermission(new RuntimePermission("setSecurityManager"))
        System.setSecurityManager(null)
      } catch {
        case e: SecurityException => println("Cannot modify security manager")
      }
    }
  }

  def bad_case_8(): Unit = {
    val action = new PrivilegedAction[Unit] {
      override def run(): Unit = {
        val permissions = new java.security.Permissions()
        // ruleid: scala-unsafe-permission
        permissions.add(new FilePermission("<<ALL FILES>>", "read,write,execute,delete"))
        permissions.add(new RuntimePermission("*"))
        
        val domain = new ProtectionDomain(null, permissions)
        println("Created domain with dangerous permissions")
      }
    }
    AccessController.doPrivileged(action)
  }

  def bad_case_9(): Unit = {
    class DangerousSecurityManager extends SecurityManager {
      override def checkRead(file: String): Unit = {
        // ruleid: scala-unsafe-permission
        // No permission check for file reads
      }
      
      override def checkWrite(file: String): Unit = {
        // No permission check for file writes
      }
      
      override def checkDelete(file: String): Unit = {
        // No permission check for file deletions
      }
    }
    System.setSecurityManager(new DangerousSecurityManager())
  }

  def bad_case_10(): Unit = {
    val context = AccessController.getContext()
    
    try {
      // ruleid: scala-unsafe-permission
      AccessController.doPrivileged(
        new PrivilegedAction[Unit] {
          override def run(): Unit = {
            System.setProperty("java.security.auth.login.config", "file:/etc/custom.conf")
          }
        },
        context
      )
    } catch {
      case e: SecurityException => println("Security exception: " + e.getMessage)
    }
  }

  def bad_case_11(): Unit = {
    val permissions = new java.security.Permissions()
    // ruleid: scala-unsafe-permission
    permissions.add(new SecurityPermission("createAccessControlContext"))
    permissions.add(new SecurityPermission("setPolicy"))
    permissions.add(new SecurityPermission("setProperty.package.access"))
    
    val pd = new ProtectionDomain(
      new CodeSource(null, Array[Certificate]()),
      permissions
    )
    
    val acc = new AccessControlContext(Array(pd))
    println("Created access control context with dangerous permissions")
  }

  def bad_case_12(): Unit = {
    val customSecurityManager = new SecurityManager() {
      override def checkPermission(perm: Permission, context: Object): Unit = {
        // ruleid: scala-unsafe-permission
        // Bypassing permission checks based on thread context
      }
    }
    System.setSecurityManager(customSecurityManager)
  }

  def bad_case_13(): Unit = {
    val action = new PrivilegedAction[Unit] {
      override def run(): Unit = {
        // ruleid: scala-unsafe-permission
        val permissions = new java.security.Permissions()
        permissions.add(new RuntimePermission("createClassLoader"))
        permissions.add(new RuntimePermission("getClassLoader"))
        permissions.add(new RuntimePermission("accessClassInPackage.*"))
        permissions.add(new RuntimePermission("defineClass"))
        
        val domain = new ProtectionDomain(null, permissions)
        println("Created domain with class loading permissions")
      }
    }
    AccessController.doPrivileged(action)
  }

  def bad_case_14(): Unit = {
    val customSecurityManager = new SecurityManager() {
      override def checkExec(cmd: String): Unit = {
        // ruleid: scala-unsafe-permission
        // Allowing all command executions without checks
      }
      
      override def checkLink(lib: String): Unit = {
        // Allowing all library loading without checks
      }
    }
    System.setSecurityManager(customSecurityManager)
  }

  def bad_case_15(): Unit = {
    try {
      // ruleid: scala-unsafe-permission
      AccessController.doPrivileged(new PrivilegedAction[Unit] {
        override def run(): Unit = {
          val permissions = new java.security.Permissions()
          permissions.add(new SocketPermission("*", "accept,connect,listen,resolve"))
          permissions.add(new NetPermission("specifyStreamHandler"))
          permissions.add(new NetPermission("setDefaultAuthenticator"))
          
          val domain = new ProtectionDomain(null, permissions)
          println("Created domain with dangerous network permissions")
        }
      })
    } catch {
      case e: SecurityException => println("Security exception: " + e.getMessage)
    }
  }

  // True Negative Examples (Safe Code)

  def good_case_1(): Unit = {
    val sm = System.getSecurityManager
    if (sm != null) {
      try {
        // ok: scala-unsafe-permission
        sm.checkPermission(new FilePermission("/tmp/app.log", "read,write"))
        println("Permission to access log file granted")
      } catch {
        case e: SecurityException => println("Permission denied: " + e.getMessage)
      }
    }
  }

  def good_case_2(): Unit = {
    val customSecurityManager = new SecurityManager() {
      override def checkPermission(perm: Permission): Unit = {
        // ok: scala-unsafe-permission
        if (perm.getName.contains("exitVM") || 
            perm.getName.contains("setSecurityManager") ||
            perm.getName.contains("createClassLoader")) {
          throw new SecurityException("Restricted permission: " + perm)
        }
        super.checkPermission(perm)
      }
    }
    try {
      System.setSecurityManager(customSecurityManager)
    } catch {
      case e: SecurityException => println("Cannot set security manager: " + e.getMessage)
    }
  }

  def good_case_3(): Unit = {
    val action = new PrivilegedAction[String] {
      override def run(): String = {
        try {
          // ok: scala-unsafe-permission
          val file = new java.io.File("/tmp/app.log")
          if (file.exists() && file.canRead()) {
            Source.fromFile(file).getLines().mkString("\n")
          } else {
            "Cannot access file"
          }
        } catch {
          case e: Exception => "Error: " + e.getMessage
        }
      }
    }
    AccessController.doPrivileged(action)
  }

  def good_case_4(): Unit = {
    class RestrictedPolicy extends Policy {
      override def getPermissions(domain: ProtectionDomain): java.security.PermissionCollection = {
        val permissions = new java.security.Permissions()
        // ok: scala-unsafe-permission
        permissions.add(new FilePermission("/tmp/-", "read"))
        permissions.add(new PropertyPermission("user.home", "read"))
        permissions.add(new SocketPermission("localhost:8000-8999", "connect,resolve"))
        permissions
      }
    }
    try {
      Policy.setPolicy(new RestrictedPolicy())
      Policy.getPolicy.refresh()
    } catch {
      case e: SecurityException => println("Cannot set policy: " + e.getMessage)
    }
  }

  def good_case_5(): Unit = {
    val sm = System.getSecurityManager
    if (sm != null) {
      try {
        // ok: scala-unsafe-permission
        sm.checkPermission(new RuntimePermission("accessDeclaredMembers"))
        println("Permission to access declared members granted")
      } catch {
        case e: SecurityException => 
          println("Permission denied: " + e.getMessage)
          // Handle the exception appropriately
      }
    }
  }

  def good_case_6(): Unit = {
    class LeastPrivilegeSecurityManager extends SecurityManager {
      override def checkPermission(perm: Permission): Unit = {
        // ok: scala-unsafe-permission
        if (perm.getName.contains("<<ALL FILES>>") || 
            perm.getName.equals("*") || 
            perm instanceof AllPermission) {
          throw new SecurityException("Overly broad permission denied: " + perm)
        }
        super.checkPermission(perm)
      }
    }
    try {
      System.setSecurityManager(new LeastPrivilegeSecurityManager())
    } catch {
      case e: SecurityException => println("Cannot set security manager: " + e.getMessage)
    }
  }

  def good_case_7(): Unit = {
    val action = new PrivilegedAction[Unit] {
      override def run(): Unit = {
        // ok: scala-unsafe-permission
        val permissions = new java.security.Permissions()
        permissions.add(new PropertyPermission("java.version", "read"))
        permissions.add(new PropertyPermission("os.name", "read"))
        permissions.add(new PropertyPermission("user.dir", "read"))
        
        val domain = new ProtectionDomain(null, permissions)
        println("Created domain with minimal read-only permissions")
      }
    }
    AccessController.doPrivileged(action)
  }

  def good_case_8(): Unit = {
    try {
      // ok: scala-unsafe-permission
      AccessController.checkPermission(new FilePermission("/app/data/config.xml", "read"))
      println("Permission check passed")
    } catch {
      case e: AccessControlException => 
        println("Permission denied: " + e.getMessage)
        // Handle the exception appropriately
    }
  }

  def good_case_9(): Unit = {
    class AppSecurityManager extends SecurityManager {
      override def checkRead(file: String): Unit = {
        // ok: scala-unsafe-permission
        if (file.contains("/etc/passwd") || file.contains("/etc/shadow")) {
          throw new SecurityException("Reading system files is not allowed")
        }
        super.checkRead(file)
      }
      
      override def checkWrite(file: String): Unit = {
        if (!file.startsWith("/tmp/") && !file.startsWith("/var/log/app/")) {
          throw new SecurityException("Writing to this location is not allowed: " + file)
        }
        super.checkWrite(file)
      }
    }
    try {
      System.setSecurityManager(new AppSecurityManager())
    } catch {
      case e: SecurityException => println("Cannot set security manager: " + e.getMessage)
    }
  }

  def good_case_10(): Unit = {
    val context = AccessController.getContext()
    
    try {
      // ok: scala-unsafe-permission
      AccessController.doPrivileged(
        new PrivilegedAction[Unit] {
          override def run(): Unit = {
            val logFile = System.getProperty("app.log.file", "/tmp/app.log")
            val writer = new java.io.FileWriter(logFile, true)
            try {
              writer.write("Log entry\n")
            } finally {
              writer.close()
            }
          }
        },
        context
      )
    } catch {
      case e: SecurityException => println("Security exception: " + e.getMessage)
    }
  }

  def good_case_11(): Unit = {
    val permissions = new java.security.Permissions()
    // ok: scala-unsafe-permission
    permissions.add(new FilePermission("/app/data/-", "read"))
    permissions.add(new SocketPermission("api.example.com:443", "connect,resolve"))
    permissions.add(new PropertyPermission("app.*", "read"))
    
    val pd = new ProtectionDomain(
      new CodeSource(null, Array[Certificate]()),
      permissions
    )
    
    val acc = new AccessControlContext(Array(pd))
    println("Created access control context with specific limited permissions")
  }

  def good_case_12(): Unit = {
    val customSecurityManager = new SecurityManager() {
      override def checkPermission(perm: Permission, context: Object): Unit = {
        // ok: scala-unsafe-permission
        if (perm instanceof AllPermission) {
          throw new SecurityException("AllPermission is not allowed")
        }
        if (perm.getName.contains("<<ALL FILES>>")) {
          throw new SecurityException("Overly broad file permission is not allowed")
        }
        super.checkPermission(perm, context)
      }
    }
    try {
      System.setSecurityManager(customSecurityManager)
    } catch {
      case e: SecurityException => println("Cannot set security manager: " + e.getMessage)
    }
  }

  def good_case_13(): Unit = {
    val action = new PrivilegedAction[Unit] {
      override def run(): Unit = {
        // ok: scala-unsafe-permission
        val permissions = new java.security.Permissions()
        permissions.add(new RuntimePermission("getProtectionDomain"))
        permissions.add(new PropertyPermission("java.home", "read"))
        permissions.add(new PropertyPermission("java.class.path", "read"))
        
        val domain = new ProtectionDomain(null, permissions)
        println("Created domain with specific limited permissions")
      }
    }
    AccessController.doPrivileged(action)
  }

  def good_case_14(): Unit = {
    class RestrictedSecurityManager extends SecurityManager {
      override def checkExec(cmd: String): Unit = {
        // ok: scala-unsafe-permission
        val allowedCommands = List("/usr/bin/ls", "/usr/bin/grep", "/usr/bin/wc")
        if (!allowedCommands.exists(cmd.startsWith)) {
          throw new SecurityException("Command execution not allowed: " + cmd)
        }
        super.checkExec(cmd)
      }
      
      override def checkLink(lib: String): Unit = {
        val allowedLibDirs = List("/usr/lib/", "/lib/")
        if (!allowedLibDirs.exists(lib.startsWith)) {
          throw new SecurityException("Loading library not allowed: " + lib)
        }
        super.checkLink(lib)
      }
    }
    try {
      System.setSecurityManager(new RestrictedSecurityManager())
    } catch {
      case e: SecurityException => println("Cannot set security manager: " + e.getMessage)
    }
  }

  def good_case_15(): Unit = {
    try {
      // ok: scala-unsafe-permission
      AccessController.doPrivileged(new PrivilegedAction[Unit] {
        override def run(): Unit = {
          val permissions = new java.security.Permissions()
          permissions.add(new SocketPermission("api.example.com:443", "connect,resolve"))
          permissions.add(new SocketPermission("db.internal:5432", "connect,resolve"))
          
          val domain = new ProtectionDomain(null, permissions)
          println("Created domain with specific network permissions")
        }
      })
    } catch {
      case e: SecurityException => println("Security exception: " + e.getMessage)
    }
  }
}