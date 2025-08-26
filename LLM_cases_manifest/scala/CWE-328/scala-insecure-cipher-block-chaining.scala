import java.security.{Key, SecureRandom}
import javax.crypto.{Cipher, KeyGenerator, SecretKey}
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import java.util.Base64
import javax.crypto.Mac
import java.security.spec.AlgorithmParameterSpec
// {fact rule=clear-text-credentials@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(): Unit = {
  // Using DES with ECB mode (both weak algorithm and insecure mode)
  val key = new SecretKeySpec("12345678".getBytes(), "DES")
  val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
  // ruleid: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_2(): Unit = {
  // Using AES with CBC mode without integrity checks
  val key = new SecretKeySpec(Array.fill(16)(0.toByte), "AES")
  val iv = new IvParameterSpec(Array.fill(16)(0.toByte))
  val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
  // ruleid: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key, iv)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_3(): Unit = {
  // Using 3DES (weak algorithm)
  val keyGen = KeyGenerator.getInstance("DESede")
  keyGen.init(168)
  val secretKey = keyGen.generateKey()
  val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding")
  val iv = new IvParameterSpec(Array.fill(8)(0.toByte))
  // ruleid: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_4(): Unit = {
  // Using AES with ECB mode (insecure mode)
  val key = new SecretKeySpec(Array.fill(16)(1.toByte), "AES")
  val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
  // ruleid: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_5(): Unit = {
  // Using DES with CBC mode (weak algorithm)
  val key = new SecretKeySpec("87654321".getBytes(), "DES")
  val iv = new IvParameterSpec("12345678".getBytes())
  val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
  // ruleid: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key, iv)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_6(): Unit = {
  // Using AES with CTR mode without integrity checks
  val key = new SecretKeySpec(Array.fill(16)(2.toByte), "AES")
  val iv = new IvParameterSpec(Array.fill(16)(2.toByte))
  val cipher = Cipher.getInstance("AES/CTR/NoPadding")
  // ruleid: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key, iv)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_7(): Unit = {
  // Using 3DES with ECB mode (both weak algorithm and insecure mode)
  val keyGen = KeyGenerator.getInstance("DESede")
  keyGen.init(168)
  val secretKey = keyGen.generateKey()
  val cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding")
  // ruleid: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, secretKey)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_8(): Unit = {
  // Using DES with CTR mode (weak algorithm)
  val key = new SecretKeySpec("abcdefgh".getBytes(), "DES")
  val iv = new IvParameterSpec("hgfedcba".getBytes())
  val cipher = Cipher.getInstance("DES/CTR/NoPadding")
  // ruleid: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key, iv)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_9(): Unit = {
  // Using string literal for algorithm specification with CBC mode
  val key = new SecretKeySpec(Array.fill(16)(3.toByte), "AES")
  val iv = new IvParameterSpec(Array.fill(16)(3.toByte))
  // ruleid: scala-insecure-cipher-block-chaining
  val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
  cipher.init(Cipher.ENCRYPT_MODE, key, iv)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_10(): Unit = {
  // Using variable for algorithm specification with ECB mode
  val algorithm = "AES/ECB/PKCS5Padding"
  val key = new SecretKeySpec(Array.fill(16)(4.toByte), "AES")
  val cipher = Cipher.getInstance(algorithm)
  // ruleid: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_11(): Unit = {
  // Using 3DES with CBC mode in a more complex scenario
  val keyBytes = Array[Byte](1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24)
  val key = new SecretKeySpec(keyBytes, "DESede")
  val iv = new IvParameterSpec(Array[Byte](0, 1, 2, 3, 4, 5, 6, 7))
  val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding")
  // ruleid: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key, iv)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_12(): Unit = {
  // Using DES with CBC mode in a function
  def encryptWithDES(data: String): Array[Byte] = {
    val key = new SecretKeySpec("12345678".getBytes(), "DES")
    val iv = new IvParameterSpec("87654321".getBytes())
    val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
    // ruleid: scala-insecure-cipher-block-chaining
    cipher.init(Cipher.ENCRYPT_MODE, key, iv)
    cipher.doFinal(data.getBytes())
  }
  
  val encrypted = encryptWithDES("Sensitive data")
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_13(): Unit = {
  // Using AES with ECB mode in a class
  class Encryptor {
    private val key = new SecretKeySpec(Array.fill(16)(5.toByte), "AES")
    private val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    
    def encrypt(data: String): Array[Byte] = {
      // ruleid: scala-insecure-cipher-block-chaining
      cipher.init(Cipher.ENCRYPT_MODE, key)
      cipher.doFinal(data.getBytes())
    }
  }
  
  val encryptor = new Encryptor()
  val encrypted = encryptor.encrypt("Sensitive data")
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_14(): Unit = {
  // Using 3DES with CTR mode
  val keyGen = KeyGenerator.getInstance("DESede")
  keyGen.init(168)
  val secretKey = keyGen.generateKey()
  val iv = new IvParameterSpec(Array.fill(8)(0.toByte))
  val cipher = Cipher.getInstance("DESede/CTR/NoPadding")
  // ruleid: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

def bad_case_15(): Unit = {
  // Using AES with CBC mode in a utility function
  object CryptoUtil {
    def encryptData(data: String): String = {
      val key = new SecretKeySpec(Array.fill(16)(6.toByte), "AES")
      val iv = new IvParameterSpec(Array.fill(16)(6.toByte))
      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      // ruleid: scala-insecure-cipher-block-chaining
      cipher.init(Cipher.ENCRYPT_MODE, key, iv)
      val encrypted = cipher.doFinal(data.getBytes())
      Base64.getEncoder.encodeToString(encrypted)
    }
  }
  
  val encrypted = CryptoUtil.encryptData("Sensitive data")
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

// True Negative Examples (Secure Code)

def good_case_1(): Unit = {
  // Using AES with GCM mode (authenticated encryption)
  val key = new SecretKeySpec(Array.fill(16)(7.toByte), "AES")
  val iv = new IvParameterSpec(Array.fill(12)(7.toByte))
  val cipher = Cipher.getInstance("AES/GCM/NoPadding")
  // ok: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key, iv)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_2(): Unit = {
  // Using AES with GCM mode and additional authentication data
  val key = new SecretKeySpec(Array.fill(16)(8.toByte), "AES")
  val random = new SecureRandom()
  val iv = new byte[12]
  random.nextBytes(iv)
  val cipher = Cipher.getInstance("AES/GCM/NoPadding")
  val paramSpec = new javax.crypto.spec.GCMParameterSpec(128, iv)
  // ok: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec)
  cipher.updateAAD("Additional authenticated data".getBytes())
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_3(): Unit = {
  // Using HMAC for integrity with AES encryption
  def encryptWithIntegrity(data: String): (Array[Byte], Array[Byte]) = {
    // Encryption
    val encKey = new SecretKeySpec(Array.fill(16)(9.toByte), "AES")
    val random = new SecureRandom()
    val iv = new byte[16]
    random.nextBytes(iv)
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(iv))
    val encrypted = cipher.doFinal(data.getBytes())
    
    // HMAC for integrity
    val macKey = new SecretKeySpec(Array.fill(32)(10.toByte), "HmacSHA256")
    val mac = Mac.getInstance("HmacSHA256")
    // ok: scala-insecure-cipher-block-chaining
    mac.init(macKey)
    mac.update(iv)
    mac.update(encrypted)
    val macValue = mac.doFinal()
    
    (encrypted, macValue)
  }
  
  val (encrypted, mac) = encryptWithIntegrity("Sensitive data")
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_4(): Unit = {
  // Using AES with GCM mode in a class
  class SecureEncryptor {
    private val key = new SecretKeySpec(Array.fill(16)(11.toByte), "AES")
    
    def encrypt(data: String): (Array[Byte], Array[Byte]) = {
      val random = new SecureRandom()
      val iv = new byte[12]
      random.nextBytes(iv)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val paramSpec = new javax.crypto.spec.GCMParameterSpec(128, iv)
      // ok: scala-insecure-cipher-block-chaining
      cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec)
      val encrypted = cipher.doFinal(data.getBytes())
      (iv, encrypted)
    }
  }
  
  val encryptor = new SecureEncryptor()
  val (iv, encrypted) = encryptor.encrypt("Sensitive data")
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_5(): Unit = {
  // Using ChaCha20-Poly1305 (authenticated encryption)
  val key = new SecretKeySpec(Array.fill(32)(12.toByte), "ChaCha20")
  val nonce = new byte[12]
  new SecureRandom().nextBytes(nonce)
  val cipher = Cipher.getInstance("ChaCha20-Poly1305")
  val paramSpec = new javax.crypto.spec.IvParameterSpec(nonce)
  // ok: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_6(): Unit = {
  // Using AES with GCM mode and secure key generation
  val keyGen = KeyGenerator.getInstance("AES")
  keyGen.init(256)
  val secretKey = keyGen.generateKey()
  val random = new SecureRandom()
  val iv = new byte[12]
  random.nextBytes(iv)
  val cipher = Cipher.getInstance("AES/GCM/NoPadding")
  val paramSpec = new javax.crypto.spec.GCMParameterSpec(128, iv)
  // ok: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_7(): Unit = {
  // Using AES with GCM mode in a utility function
  object SecureCryptoUtil {
    def encryptData(data: String): (String, String) = {
      val keyGen = KeyGenerator.getInstance("AES")
      keyGen.init(256)
      val secretKey = keyGen.generateKey()
      val random = new SecureRandom()
      val iv = new byte[12]
      random.nextBytes(iv)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val paramSpec = new javax.crypto.spec.GCMParameterSpec(128, iv)
      // ok: scala-insecure-cipher-block-chaining
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec)
      val encrypted = cipher.doFinal(data.getBytes())
      (Base64.getEncoder.encodeToString(iv), Base64.getEncoder.encodeToString(encrypted))
    }
  }
  
  val (iv, encrypted) = SecureCryptoUtil.encryptData("Sensitive data")
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_8(): Unit = {
  // Using authenticated encryption with additional data
  val key = new SecretKeySpec(Array.fill(32)(13.toByte), "ChaCha20")
  val nonce = new byte[12]
  new SecureRandom().nextBytes(nonce)
  val cipher = Cipher.getInstance("ChaCha20-Poly1305")
  val paramSpec = new javax.crypto.spec.IvParameterSpec(nonce)
  // ok: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec)
  cipher.updateAAD("Additional authenticated data".getBytes())
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_9(): Unit = {
  // Using AES with GCM mode and key derivation
  import javax.crypto.spec.PBEKeySpec
  import javax.crypto.SecretKeyFactory
  
  val password = "secure-password".toCharArray
  val salt = new Array[Byte](16)
  new SecureRandom().nextBytes(salt)
  
  // Derive key from password
  val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
  val spec = new PBEKeySpec(password, salt, 65536, 256)
  val tmp = factory.generateSecret(spec)
  val secretKey = new SecretKeySpec(tmp.getEncoded, "AES")
  
  // Encrypt with GCM
  val iv = new Array[Byte](12)
  new SecureRandom().nextBytes(iv)
  val cipher = Cipher.getInstance("AES/GCM/NoPadding")
  val paramSpec = new javax.crypto.spec.GCMParameterSpec(128, iv)
  // ok: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_10(): Unit = {
  // Using AES with GCM mode in a more complex scenario
  class SecureDataHandler {
    private val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(256)
    private val secretKey = keyGen.generateKey()
    
    def encryptAndAuthenticate(data: String, associatedData: String): (Array[Byte], Array[Byte]) = {
      val random = new SecureRandom()
      val iv = new Array[Byte](12)
      random.nextBytes(iv)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val paramSpec = new javax.crypto.spec.GCMParameterSpec(128, iv)
      // ok: scala-insecure-cipher-block-chaining
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec)
      cipher.updateAAD(associatedData.getBytes())
      val encrypted = cipher.doFinal(data.getBytes())
      (iv, encrypted)
    }
  }
  
  val handler = new SecureDataHandler()
  val (iv, encrypted) = handler.encryptAndAuthenticate("Sensitive data", "Context information")
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_11(): Unit = {
  // Using AES with GCM mode and secure random IV generation
  def secureEncrypt(data: String): (Array[Byte], Array[Byte]) = {
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(256)
    val key = keyGen.generateKey()
    
    val secureRandom = new SecureRandom()
    val iv = new Array[Byte](12)
    secureRandom.nextBytes(iv)
    
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv)
    // ok: scala-insecure-cipher-block-chaining
    cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)
    val encrypted = cipher.doFinal(data.getBytes("UTF-8"))
    
    (iv, encrypted)
  }
  
  val (iv, encrypted) = secureEncrypt("Sensitive data")
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_12(): Unit = {
  // Using AES with GCM mode in a functional style
  val encrypt = (data: String) => {
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(256)
    val key = keyGen.generateKey()
    
    val random = new SecureRandom()
    val iv = new Array[Byte](12)
    random.nextBytes(iv)
    
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv)
    // ok: scala-insecure-cipher-block-chaining
    cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)
    val encrypted = cipher.doFinal(data.getBytes())
    
    (key, iv, encrypted)
  }
  
  val (key, iv, encrypted) = encrypt("Sensitive data")
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_13(): Unit = {
  // Using AES with GCM mode and handling both encryption and decryption
  class SecureCrypto {
    private val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(256)
    private val key = keyGen.generateKey()
    
    def encrypt(data: String): (Array[Byte], Array[Byte]) = {
      val random = new SecureRandom()
      val iv = new Array[Byte](12)
      random.nextBytes(iv)
      
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv)
      // ok: scala-insecure-cipher-block-chaining
      cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)
      val encrypted = cipher.doFinal(data.getBytes())
      
      (iv, encrypted)
    }
    
    def decrypt(iv: Array[Byte], encrypted: Array[Byte]): String = {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv)
      cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)
      val decrypted = cipher.doFinal(encrypted)
      new String(decrypted)
    }
  }
  
  val crypto = new SecureCrypto()
  val (iv, encrypted) = crypto.encrypt("Sensitive data")
  val decrypted = crypto.decrypt(iv, encrypted)
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_14(): Unit = {
  // Using ChaCha20-Poly1305 with proper key and nonce generation
  val keyGen = KeyGenerator.getInstance("ChaCha20")
  keyGen.init(256)
  val key = keyGen.generateKey()
  
  val random = new SecureRandom()
  val nonce = new Array[Byte](12)
  random.nextBytes(nonce)
  
  val cipher = Cipher.getInstance("ChaCha20-Poly1305")
  val paramSpec = new javax.crypto.spec.IvParameterSpec(nonce)
  // ok: scala-insecure-cipher-block-chaining
  cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec)
  val encrypted = cipher.doFinal("Sensitive data".getBytes())
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

def good_case_15(): Unit = {
  // Using AES with GCM mode in a trait implementation
  trait Encryption {
    def encrypt(data: String): (Array[Byte], Array[Byte])
    def decrypt(iv: Array[Byte], encrypted: Array[Byte]): String
  }
  
  class AESGCMEncryption extends Encryption {
    private val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(256)
    private val key = keyGen.generateKey()
    
    override def encrypt(data: String): (Array[Byte], Array[Byte]) = {
      val random = new SecureRandom()
      val iv = new Array[Byte](12)
      random.nextBytes(iv)
      
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv)
      // ok: scala-insecure-cipher-block-chaining
      cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)
      val encrypted = cipher.doFinal(data.getBytes())
      
      (iv, encrypted)
    }
    
    override def decrypt(iv: Array[Byte], encrypted: Array[Byte]): String = {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      val gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv)
      cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)
      val decrypted = cipher.doFinal(encrypted)
      new String(decrypted)
    }
  }
  
  val encryption: Encryption = new AESGCMEncryption()
  val (iv, encrypted) = encryption.encrypt("Sensitive data")
  val decrypted = encryption.decrypt(iv, encrypted)
}
// {/fact}