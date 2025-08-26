// File: CustomMessageDigestExamples.scala

import java.security.{MessageDigest, Provider, Security}
import java.security.spec.{KeySpec, PBEKeySpec}
import javax.crypto.{Cipher, SecretKey, SecretKeyFactory}
import javax.crypto.spec.{IvParameterSpec, PBEParameterSpec, SecretKeySpec}
import scala.util.Random
import java.nio.charset.StandardCharsets
import java.util.Base64

object CustomMessageDigestExamples {

  // True Positive Examples (Vulnerable Code)

  def bad_case_1(): Unit = {
    // Custom implementation of a hash function
    class MyCustomMessageDigest {
      private var data: Array[Byte] = Array.emptyByteArray
      
      def update(input: Array[Byte]): Unit = {
        data = data ++ input
      }
      
      def digest(): Array[Byte] = {
        // ruleid: scala-custom-message-digest
        // Custom hash algorithm implementation (very weak)
        val result = Array.ofDim[Byte](16)
        for (i <- 0 until math.min(data.length, 16)) {
          result(i) = (data(i) ^ 0x42).toByte
        }
        result
      }
    }
    
    val customDigest = new MyCustomMessageDigest()
    customDigest.update("password".getBytes(StandardCharsets.UTF_8))
    val hash = customDigest.digest()
    println(Base64.getEncoder.encodeToString(hash))
  }

  def bad_case_2(): Unit = {
    // Custom hash function using XOR operations
    def customHash(input: String): Array[Byte] = {
      val bytes = input.getBytes(StandardCharsets.UTF_8)
      val result = Array.ofDim[Byte](32)
      
      // ruleid: scala-custom-message-digest
      // Custom hash implementation using XOR and rotation
      var salt = 0x5A
      for (i <- bytes.indices) {
        val pos = i % 32
        result(pos) = (result(pos) ^ (bytes(i) + salt)).toByte
        salt = (salt * 13) % 256
      }
      
      result
    }
    
    val hash = customHash("sensitive_data")
    println(Base64.getEncoder.encodeToString(hash))
  }

  def bad_case_3(): Unit = {
    // Custom message digest provider
    class CustomDigestProvider extends Provider("CustomDigest", 1.0, "Custom Digest Provider") {
      // ruleid: scala-custom-message-digest
      put("MessageDigest.CUSTOM-MD5", "com.example.CustomMD5")
    }
    
    Security.addProvider(new CustomDigestProvider())
    val md = MessageDigest.getInstance("CUSTOM-MD5")
    val hash = md.digest("password".getBytes(StandardCharsets.UTF_8))
    println(Base64.getEncoder.encodeToString(hash))
  }

  def bad_case_4(): Unit = {
    // Implementing a custom hash algorithm based on CRC
    def customCrcHash(data: String): Array[Byte] = {
      val bytes = data.getBytes(StandardCharsets.UTF_8)
      val result = Array.ofDim[Byte](16)
      
      // ruleid: scala-custom-message-digest
      // Custom CRC-based hash implementation
      var crc = 0xFFFFFFFF
      for (b <- bytes) {
        crc ^= (b & 0xFF)
        for (_ <- 0 until 8) {
          crc = if ((crc & 1) == 1) (crc >>> 1) ^ 0xEDB88320 else crc >>> 1
        }
      }
      crc = ~crc
      
      // Convert to bytes
      for (i <- 0 until 4) {
        result(i) = ((crc >>> (i * 8)) & 0xFF).toByte
      }
      
      result
    }
    
    val hash = customCrcHash("sensitive_data")
    println(Base64.getEncoder.encodeToString(hash))
  }

  def bad_case_5(): Unit = {
    // Custom hash function using a simple algorithm
    def simpleHash(input: String): Array[Byte] = {
      val bytes = input.getBytes(StandardCharsets.UTF_8)
      val result = Array.ofDim[Byte](16)
      
      // ruleid: scala-custom-message-digest
      // Simple custom hash implementation
      var h1 = 0x811C9DC5
      var h2 = 0xC9DC5118
      
      for (b <- bytes) {
        h1 = ((h1 * 16777619) ^ (b & 0xFF)) & 0xFFFFFFFF
        h2 = ((h2 * 16777619) ^ (b & 0xFF)) & 0xFFFFFFFF
      }
      
      // Convert to bytes
      for (i <- 0 until 4) {
        result(i) = ((h1 >>> (i * 8)) & 0xFF).toByte
        result(i + 4) = ((h2 >>> (i * 8)) & 0xFF).toByte
      }
      
      result
    }
    
    val hash = simpleHash("password123")
    println(Base64.getEncoder.encodeToString(hash))
  }

  def bad_case_6(): Unit = {
    // Custom encryption algorithm
    class CustomEncryption {
      private val key = Array[Byte](1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
      
      def encrypt(data: Array[Byte]): Array[Byte] = {
        // ruleid: scala-custom-message-digest
        // Custom encryption algorithm (very weak)
        val result = Array.ofDim[Byte](data.length)
        for (i <- data.indices) {
          result(i) = (data(i) ^ key(i % key.length)).toByte
        }
        result
      }
      
      def decrypt(data: Array[Byte]): Array[Byte] = {
        // Same as encrypt since XOR is symmetric
        encrypt(data)
      }
    }
    
    val encryption = new CustomEncryption()
    val encrypted = encryption.encrypt("secret message".getBytes(StandardCharsets.UTF_8))
    println(Base64.getEncoder.encodeToString(encrypted))
  }

  def bad_case_7(): Unit = {
    // Custom hash function using a non-standard approach
    object NonStandardHash {
      // ruleid: scala-custom-message-digest
      def hash(input: String): String = {
        val bytes = input.getBytes(StandardCharsets.UTF_8)
        val result = new StringBuilder
        
        var accumulator = 0x12345678
        for (b <- bytes) {
          accumulator = (accumulator * 65537 + b) & 0xFFFFFFFF
          result.append(f"${accumulator & 0xFF}%02x")
        }
        
        result.toString
      }
    }
    
    val hash = NonStandardHash.hash("my_password")
    println(hash)
  }

  def bad_case_8(): Unit = {
    // Custom message digest implementation using a mix of algorithms
    class HybridDigest {
      private var buffer = Array.emptyByteArray
      
      def update(data: Array[Byte]): Unit = {
        buffer = buffer ++ data
      }
      
      def digest(): Array[Byte] = {
        // ruleid: scala-custom-message-digest
        // Custom hybrid digest algorithm
        val result = Array.ofDim[Byte](32)
        
        // First half - custom algorithm
        var h = 0x811C9DC5
        for (b <- buffer) {
          h = ((h * 16777619) ^ (b & 0xFF)) & 0xFFFFFFFF
          h = (h << 1) | (h >>> 31)  // rotate left by 1
        }
        
        for (i <- 0 until 16) {
          result(i) = ((h >>> (i % 4 * 8)) & 0xFF).toByte
        }
        
        // Second half - another custom algorithm
        h = 0xC9DC5118
        for (b <- buffer.reverse) {
          h = ((h * 33) ^ (b & 0xFF)) & 0xFFFFFFFF
        }
        
        for (i <- 0 until 16) {
          result(i + 16) = ((h >>> (i % 4 * 8)) & 0xFF).toByte
        }
        
        result
      }
    }
    
    val digest = new HybridDigest()
    digest.update("sensitive_information".getBytes(StandardCharsets.UTF_8))
    val hash = digest.digest()
    println(Base64.getEncoder.encodeToString(hash))
  }

  def bad_case_9(): Unit = {
    // Custom HMAC implementation
    object CustomHMAC {
      // ruleid: scala-custom-message-digest
      def hmac(key: Array[Byte], message: Array[Byte]): Array[Byte] = {
        val blockSize = 64
        val outputSize = 20
        
        // Prepare key
        val workingKey = if (key.length > blockSize) {
          // Use custom hash if key is too long
          val hashedKey = Array.ofDim[Byte](outputSize)
          for (i <- 0 until outputSize) {
            hashedKey(i) = (key(i % key.length) ^ 0x36).toByte
          }
          hashedKey
        } else if (key.length < blockSize) {
          // Pad key if too short
          val paddedKey = Array.ofDim[Byte](blockSize)
          Array.copy(key, 0, paddedKey, 0, key.length)
          paddedKey
        } else {
          key
        }
        
        // Inner padding
        val innerPad = Array.ofDim[Byte](blockSize)
        for (i <- 0 until blockSize) {
          innerPad(i) = (workingKey(i) ^ 0x36).toByte
        }
        
        // Outer padding
        val outerPad = Array.ofDim[Byte](blockSize)
        for (i <- 0 until blockSize) {
          outerPad(i) = (workingKey(i) ^ 0x5c).toByte
        }
        
        // Custom hash function
        def customHash(data: Array[Byte]): Array[Byte] = {
          val result = Array.ofDim[Byte](outputSize)
          var h = 0x67452301
          
          for (b <- data) {
            h = ((h << 5) | (h >>> 27)) + (b & 0xFF)
          }
          
          for (i <- 0 until outputSize) {
            result(i) = ((h >>> (i % 4 * 8)) & 0xFF).toByte
          }
          
          result
        }
        
        // Inner hash
        val innerResult = customHash(innerPad ++ message)
        
        // Outer hash
        customHash(outerPad ++ innerResult)
      }
    }
    
    val key = "secret_key".getBytes(StandardCharsets.UTF_8)
    val message = "message_to_authenticate".getBytes(StandardCharsets.UTF_8)
    val mac = CustomHMAC.hmac(key, message)
    println(Base64.getEncoder.encodeToString(mac))
  }

  def bad_case_10(): Unit = {
    // Custom key derivation function
    object CustomKDF {
      // ruleid: scala-custom-message-digest
      def deriveKey(password: String, salt: Array[Byte], iterations: Int): Array[Byte] = {
        var key = password.getBytes(StandardCharsets.UTF_8)
        
        // Custom key stretching
        for (_ <- 0 until iterations) {
          val newKey = Array.ofDim[Byte](key.length + salt.length)
          
          // Mix password and salt
          for (i <- key.indices) {
            newKey(i) = key(i)
          }
          
          for (i <- salt.indices) {
            newKey(key.length + i) = salt(i)
          }
          
          // Simple custom hash
          key = Array.ofDim[Byte](32)
          var h = 0x811C9DC5
          
          for (b <- newKey) {
            h = ((h * 16777619) ^ (b & 0xFF)) & 0xFFFFFFFF
            h = (h << 7) | (h >>> 25)  // rotate left by 7
          }
          
          for (i <- 0 until 32) {
            key(i) = ((h >>> (i % 4 * 8)) & 0xFF).toByte
          }
        }
        
        key
      }
    }
    
    val salt = Array[Byte](1, 2, 3, 4, 5, 6, 7, 8)
    val derivedKey = CustomKDF.deriveKey("password123", salt, 1000)
    println(Base64.getEncoder.encodeToString(derivedKey))
  }

  def bad_case_11(): Unit = {
    // Custom password hashing scheme
    class CustomPasswordHasher {
      private val salt = Array[Byte](10, 20, 30, 40, 50, 60, 70, 80)
      
      // ruleid: scala-custom-message-digest
      def hashPassword(password: String): String = {
        val passwordBytes = password.getBytes(StandardCharsets.UTF_8)
        val saltedPassword = passwordBytes ++ salt
        
        // Custom hash function
        val hash = Array.ofDim[Byte](32)
        var h1 = 0x67452301
        var h2 = 0xEFCDAB89
        
        for (i <- saltedPassword.indices) {
          val b = saltedPassword(i)
          h1 = ((h1 << 5) + h1) ^ (b & 0xFF)
          h2 = ((h2 << 7) + h2) ^ (b & 0xFF)
        }
        
        for (i <- 0 until 16) {
          hash(i) = ((h1 >>> (i % 4 * 8)) & 0xFF).toByte
          hash(i + 16) = ((h2 >>> (i % 4 * 8)) & 0xFF).toByte
        }
        
        Base64.getEncoder.encodeToString(hash)
      }
    }
    
    val hasher = new CustomPasswordHasher()
    val hashedPassword = hasher.hashPassword("mySecurePassword")
    println(hashedPassword)
  }

  def bad_case_12(): Unit = {
    // Custom cipher implementation
    class CustomCipher {
      private val key = "secretkey123456".getBytes(StandardCharsets.UTF_8)
      
      // ruleid: scala-custom-message-digest
      def encrypt(data: Array[Byte]): Array[Byte] = {
        val result = Array.ofDim[Byte](data.length)
        
        // Generate keystream using custom PRNG
        val keystream = Array.ofDim[Byte](data.length)
        var seed = 0x12345678
        
        for (i <- keystream.indices) {
          seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
          keystream(i) = (seed & 0xFF).toByte
        }
        
        // XOR data with keystream
        for (i <- data.indices) {
          result(i) = (data(i) ^ keystream(i) ^ key(i % key.length)).toByte
        }
        
        result
      }
      
      def decrypt(data: Array[Byte]): Array[Byte] = {
        // Same as encrypt since the operation is symmetric
        encrypt(data)
      }
    }
    
    val cipher = new CustomCipher()
    val encrypted = cipher.encrypt("sensitive data".getBytes(StandardCharsets.UTF_8))
    println(Base64.getEncoder.encodeToString(encrypted))
  }

  def bad_case_13(): Unit = {
    // Custom hash function using bit manipulation
    object BitManipulationHash {
      // ruleid: scala-custom-message-digest
      def hash(input: String): Array[Byte] = {
        val data = input.getBytes(StandardCharsets.UTF_8)
        val result = Array.ofDim[Byte](32)
        
        // Initialize hash state
        val state = Array.fill(8)(0xAAAAAAAA)
        
        // Process each byte
        for (b <- data) {
          // Update state with custom mixing function
          for (i <- state.indices) {
            state(i) = state(i) ^ (b & 0xFF)
            state(i) = ((state(i) << 11) | (state(i) >>> 21)) & 0xFFFFFFFF
            state(i) = state(i) * 0x01010101 & 0xFFFFFFFF
          }
          
          // Mix state elements
          for (i <- 0 until state.length - 1) {
            state(i) = (state(i) + state(i + 1)) & 0xFFFFFFFF
          }
          state(state.length - 1) = (state(state.length - 1) + state(0)) & 0xFFFFFFFF
        }
        
        // Convert state to bytes
        for (i <- 0 until 8) {
          val value = state(i)
          for (j <- 0 until 4) {
            result(i * 4 + j) = ((value >>> (j * 8)) & 0xFF).toByte
          }
        }
        
        result
      }
    }
    
    val hash = BitManipulationHash.hash("password123")
    println(Base64.getEncoder.encodeToString(hash))
  }

  def bad_case_14(): Unit = {
    // Custom message authentication code
    class CustomMAC {
      private val key = "authentication_key".getBytes(StandardCharsets.UTF_8)
      
      // ruleid: scala-custom-message-digest
      def generateMAC(message: Array[Byte]): Array[Byte] = {
        val result = Array.ofDim[Byte](16)
        
        // Initialize MAC state
        var state = 0x67452301L
        
        // Process key and message
        for (b <- key ++ message) {
          // Update state with custom mixing function
          state ^= (b & 0xFF)
          state = ((state << 7) | (state >>> 57)) & 0xFFFFFFFFFFFFFFFFL
          state = (state * 0x5DEECE66DL + 0xBL) & 0xFFFFFFFFFFFFFFFFL
        }
        
        // Convert state to bytes
        for (i <- 0 until 8) {
          result(i) = ((state >>> (i * 8)) & 0xFF).toByte
        }
        
        // Add a simple checksum
        var checksum = 0
        for (i <- 0 until 8) {
          checksum = (checksum + (result(i) & 0xFF)) & 0xFF
        }
        
        for (i <- 8 until 16) {
          result(i) = ((checksum ^ (i * 0x11)) & 0xFF).toByte
          checksum = (checksum * 13) & 0xFF
        }
        
        result
      }
    }
    
    val mac = new CustomMAC()
    val authCode = mac.generateMAC("message to authenticate".getBytes(StandardCharsets.UTF_8))
    println(Base64.getEncoder.encodeToString(authCode))
  }

  def bad_case_15(): Unit = {
    // Custom hash function with multiple rounds
    object MultiRoundHash {
      // ruleid: scala-custom-message-digest
      def hash(input: String): Array[Byte] = {
        var data = input.getBytes(StandardCharsets.UTF_8)
        
        // Multiple rounds of custom hashing
        for (_ <- 0 until 10) {
          // Round 1: XOR folding
          val round1 = Array.ofDim[Byte](32)
          for (i <- data.indices) {
            round1(i % 32) = (round1(i % 32) ^ data(i)).toByte
          }
          
          // Round 2: Bit rotation
          val round2 = Array.ofDim[Byte](32)
          for (i <- 0 until 32) {
            val rotAmount = (i % 7) + 1
            val value = round1(i) & 0xFF
            round2(i) = ((value << rotAmount) | (value >>> (8 - rotAmount)) & 0xFF).toByte
          }
          
          // Round 3: Substitution
          val round3 = Array.ofDim[Byte](32)
          for (i <- 0 until 32) {
            round3(i) = (((round2(i) & 0xFF) * 0x0F) ^ 0xAA).toByte
          }
          
          data = round3
        }
        
        data
      }
    }
    
    val hash = MultiRoundHash.hash("secure_password")
    println(Base64.getEncoder.encodeToString(hash))
  }

  // True Negative Examples (Secure Code)

  def good_case_1(): Unit = {
    // ok: scala-custom-message-digest
    val md = MessageDigest.getInstance("SHA-256")
    val hash = md.digest("password".getBytes(StandardCharsets.UTF_8))
    println(Base64.getEncoder.encodeToString(hash))
  }

  def good_case_2(): Unit = {
    // ok: scala-custom-message-digest
    val md = MessageDigest.getInstance("SHA-512")
    md.update("part1".getBytes(StandardCharsets.UTF_8))
    md.update("part2".getBytes(StandardCharsets.UTF_8))
    val hash = md.digest()
    println(Base64.getEncoder.encodeToString(hash))
  }

  def good_case_3(): Unit = {
    // Using standard HMAC implementation
    import javax.crypto.Mac
    import javax.crypto.spec.SecretKeySpec
    
    val key = "secret_key".getBytes(StandardCharsets.UTF_8)
    val message = "message_to_authenticate".getBytes(StandardCharsets.UTF_8)
    
    // ok: scala-custom-message-digest
    val mac = Mac.getInstance("HmacSHA256")
    val secretKeySpec = new SecretKeySpec(key, "HmacSHA256")
    mac.init(secretKeySpec)
    val hmac = mac.doFinal(message)
    
    println(Base64.getEncoder.encodeToString(hmac))
  }

  def good_case_4(): Unit = {
    // Using standard PBKDF2 for password hashing
    val password = "password123".toCharArray
    val salt = new Array[Byte](16)
    new Random().nextBytes(salt)
    
    // ok: scala-custom-message-digest
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val spec = new PBEKeySpec(password, salt, 65536, 256)
    val key = factory.generateSecret(spec)
    val hash = key.getEncoded
    
    println(Base64.getEncoder.encodeToString(hash))
  }

  def good_case_5(): Unit = {
    // Using standard AES encryption
    val key = new Array[Byte](16)
    new Random().nextBytes(key)
    val iv = new Array[Byte](16)
    new Random().nextBytes(iv)
    
    // ok: scala-custom-message-digest
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val secretKey = new SecretKeySpec(key, "AES")
    val ivSpec = new IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val encrypted = cipher.doFinal("sensitive data".getBytes(StandardCharsets.UTF_8))
    println(Base64.getEncoder.encodeToString(encrypted))
  }

  def good_case_6(): Unit = {
    // Using SHA-3 (Secure Hash Algorithm 3)
    val data = "important_data".getBytes(StandardCharsets.UTF_8)
    
    // ok: scala-custom-message-digest
    val md = MessageDigest.getInstance("SHA3-256")
    val hash = md.digest(data)
    
    println(Base64.getEncoder.encodeToString(hash))
  }

  def good_case_7(): Unit = {
    // Using standard password hashing with bcrypt
    import org.mindrot.jbcrypt.BCrypt
    
    val password = "secure_password"
    
    // ok: scala-custom-message-digest
    val hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12))
    
    println(hashedPassword)
    
    // Verify password
    val isValid = BCrypt.checkpw(password, hashedPassword)
    println(s"Password valid: $isValid")
  }

  def good_case_8(): Unit = {
    // Using standard RSA encryption
    import java.security.KeyPairGenerator
    import javax.crypto.Cipher
    
    // Generate key pair
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(2048)
    val keyPair = keyGen.generateKeyPair()
    
    val data = "sensitive information".getBytes(StandardCharsets.UTF_8)
    
    // ok: scala-custom-message-digest
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic)
    val encrypted = cipher.doFinal(data)
    
    println(Base64.getEncoder.encodeToString(encrypted))
  }

  def good_case_9(): Unit = {
    // Using standard HMAC with SHA-512
    import javax.crypto.Mac
    import javax.crypto.spec.SecretKeySpec
    
    val key = "very_secure_key".getBytes(StandardCharsets.UTF_8)
    val data = "data_to_authenticate".getBytes(StandardCharsets.UTF_8)
    
    // ok: scala-custom-message-digest
    val mac = Mac.getInstance("HmacSHA512")
    val secretKey = new SecretKeySpec(key, "HmacSHA512")
    mac.init(secretKey)
    val result = mac.doFinal(data)
    
    println(Base64.getEncoder.encodeToString(result))
  }

  def good_case_10(): Unit = {
    // Using standard key derivation with PBKDF2
    val password = "user_password".toCharArray
    val salt = new Array[Byte](16)
    new Random().nextBytes(salt)
    
    // ok: scala-custom-message-digest
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
    val spec = new PBEKeySpec(password, salt, 100000, 512)
    val secretKey = factory.generateSecret(spec)
    val derivedKey = secretKey.getEncoded
    
    println(Base64.getEncoder.encodeToString(derivedKey))
  }

  def good_case_11(): Unit = {
    // Using standard AES-GCM encryption (authenticated encryption)
    val key = new Array[Byte](32) // 256 bits
    new Random().nextBytes(key)
    val iv = new Array[Byte](12) // 96 bits for GCM
    new Random().nextBytes(iv)
    
    // ok: scala-custom-message-digest
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val secretKey = new SecretKeySpec(key, "AES")
    val ivSpec = new IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val encrypted = cipher.doFinal("sensitive data with authentication".getBytes(StandardCharsets.UTF_8))
    println(Base64.getEncoder.encodeToString(encrypted))
  }

  def good_case_12(): Unit = {
    // Using standard SHA-256 with salting
    val password = "user_password"
    val salt = new Array[Byte](16)
    new Random().nextBytes(salt)
    
    // ok: scala-custom-message-digest
    val md = MessageDigest.getInstance("SHA-256")
    md.update(salt)
    md.update(password.getBytes(StandardCharsets.UTF_8))
    val hash = md.digest()
    
    // Store both salt and hash
    val saltAndHash = salt ++ hash
    println(Base64.getEncoder.encodeToString(saltAndHash))
  }

  def good_case_13(): Unit = {
    // Using standard ChaCha20-Poly1305 encryption
    import javax.crypto.Cipher
    import javax.crypto.spec.{ChaCha20ParameterSpec, SecretKeySpec}
    
    val key = new Array[Byte](32) // 256 bits
    new Random().nextBytes(key)
    val nonce = new Array[Byte](12)
    new Random().nextBytes(nonce)
    val counter = 1 // Initial counter value
    
    // ok: scala-custom-message-digest
    val cipher = Cipher.getInstance("ChaCha20-Poly1305")
    val secretKey = new SecretKeySpec(key, "ChaCha20")
    val paramSpec = new ChaCha20ParameterSpec(nonce, counter)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec)
    
    val encrypted = cipher.doFinal("secure data".getBytes(StandardCharsets.UTF_8))
    println(Base64.getEncoder.encodeToString(encrypted))
  }

  def good_case_14(): Unit = {
    // Using standard Argon2 password hashing (via library)
    import org.bouncycastle.crypto.generators.Argon2BytesGenerator
    import org.bouncycastle.crypto.params.Argon2Parameters
    
    val password = "secure_password".getBytes(StandardCharsets.UTF_8)
    val salt = new Array[Byte](16)
    new Random().nextBytes(salt)
    
    // ok: scala-custom-message-digest
    val builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
      .withSalt(salt)
      .withIterations(3)
      .withMemoryAsKB(65536)
      .withParallelism(4)
    
    val generator = new Argon2BytesGenerator()
    generator.init(builder.build())
    
    val hash = new Array[Byte](32)
    generator.generateBytes(password, hash)
    
    println(Base64.getEncoder.encodeToString(hash))
  }

  def good_case_15(): Unit = {
    // Using standard Blake2b hash function
    import org.bouncycastle.crypto.digests.Blake2bDigest
    
    val data = "data_to_hash".getBytes(StandardCharsets.UTF_8)
    
    // ok: scala-custom-message-digest
    val digest = new Blake2bDigest(256) // 256 bits output
    digest.update(data, 0, data.length)
    
    val hash = new Array[Byte](32) // 256 bits = 32 bytes
    digest.doFinal(hash, 0)
    
    println(Base64.getEncoder.encodeToString(hash))
  }
}