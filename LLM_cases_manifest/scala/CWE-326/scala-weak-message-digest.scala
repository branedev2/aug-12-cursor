import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.util.{Try, Success, Failure}
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import org.apache.commons.codec.digest.DigestUtils
import java.security.SecureRandom
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(): Unit = {
  val input = "sensitive data"
  val md = MessageDigest.getInstance("MD5")
  // ruleid: scala-weak-message-digest
  val hash = md.digest(input.getBytes("UTF-8"))
  println(s"MD5 hash: ${bytesToHex(hash)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_2(): Unit = {
  val password = "user_password"
  // ruleid: scala-weak-message-digest
  val hashedPassword = DigestUtils.md5Hex(password)
  println(s"Hashed password: $hashedPassword")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_3(): Unit = {
  val data = "important information"
  val md = MessageDigest.getInstance("SHA-1")
  // ruleid: scala-weak-message-digest
  val hash = md.digest(data.getBytes(StandardCharsets.UTF_8))
  val hexString = new BigInteger(1, hash).toString(16)
  println(s"SHA-1 hash: $hexString")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_4(): Unit = {
  val userData = "user credentials"
  // ruleid: scala-weak-message-digest
  val hashedData = DigestUtils.sha1Hex(userData)
  println(s"Hashed user data: $hashedData")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_5(): Unit = {
  val sensitiveInfo = "credit card number"
  val md = MessageDigest.getInstance("MD2")
  // ruleid: scala-weak-message-digest
  val hash = md.digest(sensitiveInfo.getBytes())
  println(s"MD2 hash: ${bytesToHex(hash)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_6(): Unit = {
  val fileContent = "document content"
  // ruleid: scala-weak-message-digest
  val checksum = DigestUtils.md4Hex(fileContent)
  println(s"File checksum: $checksum")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_7(): Unit = {
  val secretKey = "my-secret-key".getBytes("UTF-8")
  val data = "data to be authenticated"
  val mac = Mac.getInstance("HmacMD5")
  val keySpec = new SecretKeySpec(secretKey, "HmacMD5")
  mac.init(keySpec)
  // ruleid: scala-weak-message-digest
  val hmac = mac.doFinal(data.getBytes("UTF-8"))
  println(s"HMAC-MD5: ${bytesToHex(hmac)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_8(): Unit = {
  val input = "user input"
  val algorithm = "SHA1"
  val md = MessageDigest.getInstance(algorithm)
  // ruleid: scala-weak-message-digest
  val digest = md.digest(input.getBytes())
  println(s"$algorithm hash: ${bytesToHex(digest)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_9(): Unit = {
  val password = "password123"
  val salt = "salt"
  val md = MessageDigest.getInstance("MD5")
  md.update(salt.getBytes())
  // ruleid: scala-weak-message-digest
  val hashedPassword = md.digest(password.getBytes())
  println(s"Salted MD5: ${bytesToHex(hashedPassword)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_10(): Unit = {
  val data = "sensitive data"
  val secretKey = "key".getBytes("UTF-8")
  val mac = Mac.getInstance("HmacSHA1")
  val keySpec = new SecretKeySpec(secretKey, "HmacSHA1")
  mac.init(keySpec)
  // ruleid: scala-weak-message-digest
  val hmac = mac.doFinal(data.getBytes("UTF-8"))
  println(s"HMAC-SHA1: ${bytesToHex(hmac)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_11(): Unit = {
  def hashPassword(password: String): String = {
    val md = MessageDigest.getInstance("SHA1")
    // ruleid: scala-weak-message-digest
    val hash = md.digest(password.getBytes())
    bytesToHex(hash)
  }
  
  val userPassword = "secret123"
  val hashedPassword = hashPassword(userPassword)
  println(s"Hashed: $hashedPassword")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_12(): Unit = {
  val algorithms = List("MD5", "SHA-256", "MD2", "SHA-512")
  val data = "test data"
  
  for (algo <- algorithms) {
    Try {
      val md = MessageDigest.getInstance(algo)
      if (algo == "MD5" || algo == "MD2") {
        // ruleid: scala-weak-message-digest
        val hash = md.digest(data.getBytes())
        println(s"$algo hash: ${bytesToHex(hash)}")
      } else {
        val hash = md.digest(data.getBytes())
        println(s"$algo hash: ${bytesToHex(hash)}")
      }
    } match {
      case Success(_) => println(s"$algo completed")
      case Failure(e) => println(s"$algo failed: ${e.getMessage}")
    }
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_13(): Unit = {
  class PasswordHasher {
    private val algorithm = "SHA1"
    
    def hash(password: String): String = {
      val md = MessageDigest.getInstance(algorithm)
      // ruleid: scala-weak-message-digest
      val digest = md.digest(password.getBytes())
      bytesToHex(digest)
    }
  }
  
  val hasher = new PasswordHasher()
  val hashedPassword = hasher.hash("myPassword")
  println(s"Hashed password: $hashedPassword")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_14(): Unit = {
  val config = Map(
    "algorithm" -> "MD5",
    "iterations" -> "1000"
  )
  
  val data = "sensitive data"
  val md = MessageDigest.getInstance(config("algorithm"))
  
  // ruleid: scala-weak-message-digest
  var hash = md.digest(data.getBytes())
  val iterations = config("iterations").toInt
  
  for (_ <- 1 until iterations) {
    md.reset()
    hash = md.digest(hash)
  }
  
  println(s"Iterated hash: ${bytesToHex(hash)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_15(): Unit = {
  trait Hasher {
    def hash(data: String): Array[Byte]
  }
  
  class MD5Hasher extends Hasher {
    override def hash(data: String): Array[Byte] = {
      val md = MessageDigest.getInstance("MD5")
      // ruleid: scala-weak-message-digest
      md.digest(data.getBytes())
    }
  }
  
  val hasher: Hasher = new MD5Hasher()
  val hash = hasher.hash("important data")
  println(s"Hash: ${bytesToHex(hash)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// True Negatives (Secure Code)

def good_case_1(): Unit = {
  val input = "sensitive data"
  val md = MessageDigest.getInstance("SHA-256")
  // ok: scala-weak-message-digest
  val hash = md.digest(input.getBytes("UTF-8"))
  println(s"SHA-256 hash: ${bytesToHex(hash)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_2(): Unit = {
  val password = "user_password"
  // ok: scala-weak-message-digest
  val hashedPassword = DigestUtils.sha512Hex(password)
  println(s"Hashed password: $hashedPassword")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_3(): Unit = {
  val data = "important information"
  val md = MessageDigest.getInstance("SHA-384")
  // ok: scala-weak-message-digest
  val hash = md.digest(data.getBytes(StandardCharsets.UTF_8))
  val hexString = new BigInteger(1, hash).toString(16)
  println(s"SHA-384 hash: $hexString")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_4(): Unit = {
  val userData = "user credentials"
  // ok: scala-weak-message-digest
  val hashedData = DigestUtils.sha256Hex(userData)
  println(s"Hashed user data: $hashedData")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_5(): Unit = {
  val secretKey = "my-secret-key".getBytes("UTF-8")
  val data = "data to be authenticated"
  val mac = Mac.getInstance("HmacSHA256")
  val keySpec = new SecretKeySpec(secretKey, "HmacSHA256")
  mac.init(keySpec)
  // ok: scala-weak-message-digest
  val hmac = mac.doFinal(data.getBytes("UTF-8"))
  println(s"HMAC-SHA256: ${bytesToHex(hmac)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_6(): Unit = {
  val password = "password123"
  val salt = new Array[Byte](16)
  new SecureRandom().nextBytes(salt)
  
  val md = MessageDigest.getInstance("SHA-512")
  md.update(salt)
  // ok: scala-weak-message-digest
  val hashedPassword = md.digest(password.getBytes())
  println(s"Salted SHA-512: ${bytesToHex(hashedPassword)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_7(): Unit = {
  import javax.crypto.SecretKeyFactory
  import javax.crypto.spec.PBEKeySpec
  
  val password = "password123"
  val salt = new Array[Byte](16)
  new SecureRandom().nextBytes(salt)
  
  val spec = new PBEKeySpec(password.toCharArray, salt, 65536, 256)
  val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
  // ok: scala-weak-message-digest
  val hash = factory.generateSecret(spec).getEncoded
  println(s"PBKDF2 hash: ${bytesToHex(hash)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_8(): Unit = {
  val data = "sensitive data"
  val secretKey = "key".getBytes("UTF-8")
  val mac = Mac.getInstance("HmacSHA512")
  val keySpec = new SecretKeySpec(secretKey, "HmacSHA512")
  mac.init(keySpec)
  // ok: scala-weak-message-digest
  val hmac = mac.doFinal(data.getBytes("UTF-8"))
  println(s"HMAC-SHA512: ${bytesToHex(hmac)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_9(): Unit = {
  def hashPassword(password: String): String = {
    val md = MessageDigest.getInstance("SHA-256")
    // ok: scala-weak-message-digest
    val hash = md.digest(password.getBytes())
    bytesToHex(hash)
  }
  
  val userPassword = "secret123"
  val hashedPassword = hashPassword(userPassword)
  println(s"Hashed: $hashedPassword")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_10(): Unit = {
  val algorithms = List("SHA-256", "SHA-384", "SHA-512")
  val data = "test data"
  
  for (algo <- algorithms) {
    Try {
      val md = MessageDigest.getInstance(algo)
      // ok: scala-weak-message-digest
      val hash = md.digest(data.getBytes())
      println(s"$algo hash: ${bytesToHex(hash)}")
    } match {
      case Success(_) => println(s"$algo completed")
      case Failure(e) => println(s"$algo failed: ${e.getMessage}")
    }
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_11(): Unit = {
  class PasswordHasher {
    private val algorithm = "SHA-256"
    
    def hash(password: String): String = {
      val md = MessageDigest.getInstance(algorithm)
      // ok: scala-weak-message-digest
      val digest = md.digest(password.getBytes())
      bytesToHex(digest)
    }
  }
  
  val hasher = new PasswordHasher()
  val hashedPassword = hasher.hash("myPassword")
  println(s"Hashed password: $hashedPassword")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_12(): Unit = {
  val config = Map(
    "algorithm" -> "SHA-512",
    "iterations" -> "1000"
  )
  
  val data = "sensitive data"
  val md = MessageDigest.getInstance(config("algorithm"))
  
  // ok: scala-weak-message-digest
  var hash = md.digest(data.getBytes())
  val iterations = config("iterations").toInt
  
  for (_ <- 1 until iterations) {
    md.reset()
    hash = md.digest(hash)
  }
  
  println(s"Iterated hash: ${bytesToHex(hash)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_13(): Unit = {
  trait Hasher {
    def hash(data: String): Array[Byte]
  }
  
  class SHA256Hasher extends Hasher {
    override def hash(data: String): Array[Byte] = {
      val md = MessageDigest.getInstance("SHA-256")
      // ok: scala-weak-message-digest
      md.digest(data.getBytes())
    }
  }
  
  val hasher: Hasher = new SHA256Hasher()
  val hash = hasher.hash("important data")
  println(s"Hash: ${bytesToHex(hash)}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_14(): Unit = {
  import org.bouncycastle.crypto.digests.SHA3Digest
  import org.bouncycastle.util.encoders.Hex
  
  val data = "sensitive data".getBytes("UTF-8")
  val digest = new SHA3Digest(256)
  val hash = new Array[Byte](digest.getDigestSize)
  
  digest.update(data, 0, data.length)
  // ok: scala-weak-message-digest
  digest.doFinal(hash, 0)
  
  println(s"SHA3-256: ${new String(Hex.encode(hash))}")
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_15(): Unit = {
  import org.mindrot.jbcrypt.BCrypt
  
  val password = "user_password"
  val salt = BCrypt.gensalt(12)
  // ok: scala-weak-message-digest
  val hashedPassword = BCrypt.hashpw(password, salt)
  
  println(s"BCrypt hash: $hashedPassword")
}
// {/fact}

// Helper function for byte array to hex string conversion
def bytesToHex(bytes: Array[Byte]): String = {
  val hexString = new StringBuilder(2 * bytes.length)
  for (b <- bytes) {
    val hex = Integer.toHexString(0xff & b)
    if (hex.length == 1) {
      hexString.append('0')
    }
    hexString.append(hex)
  }
  hexString.toString
}