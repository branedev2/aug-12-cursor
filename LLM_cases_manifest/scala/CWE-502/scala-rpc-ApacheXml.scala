import java.security.{KeyPair, KeyPairGenerator, PrivateKey, PublicKey}
import javax.crypto.Cipher
import java.util.Base64
import org.apache.commons.crypto.cipher.CryptoCipher
import org.apache.commons.crypto.utils.Utils
import java.security.spec.{MGF1ParameterSpec, OAEPParameterSpec, PSource}
import javax.crypto.spec.{OAEPParameterSpec, PSource}
import java.nio.charset.StandardCharsets
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  val publicKey = keyPair.getPublic()
  
  val cipher = Cipher.getInstance("RSA")
  // ruleid: scala-rpc-ApacheXml
  cipher.init(Cipher.ENCRYPT_MODE, publicKey)
  val plainText = "Sensitive data"
  val cipherText = cipher.doFinal(plainText.getBytes("UTF-8"))
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_2(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  val publicKey = keyPair.getPublic()
  val privateKey = keyPair.getPrivate()
  
  // ruleid: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
  cipher.init(Cipher.ENCRYPT_MODE, publicKey)
  val plainText = "Sensitive data needs encryption"
  val cipherText = cipher.doFinal(plainText.getBytes("UTF-8"))
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_3(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  val publicKey = keyPair.getPublic()
  
  val data = "Secret message"
  // ruleid: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
  cipher.init(Cipher.ENCRYPT_MODE, publicKey)
  val encryptedData = cipher.doFinal(data.getBytes())
  val encodedData = Base64.getEncoder.encodeToString(encryptedData)
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_4(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  val publicKey = keyPair.getPublic()
  val privateKey = keyPair.getPrivate()
  
  val message = "This is a confidential message"
  
  // ruleid: scala-rpc-ApacheXml
  val encryptCipher = Cipher.getInstance("RSA")
  encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey)
  val encryptedBytes = encryptCipher.doFinal(message.getBytes(StandardCharsets.UTF_8))
  
  val decryptCipher = Cipher.getInstance("RSA")
  decryptCipher.init(Cipher.DECRYPT_MODE, privateKey)
  val decryptedBytes = decryptCipher.doFinal(encryptedBytes)
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_5(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val algorithm = "RSA/ECB/PKCS1Padding"
  // ruleid: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance(algorithm)
  cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
  val encrypted = cipher.doFinal("Sensitive information".getBytes("UTF-8"))
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_6(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val data = "Confidential data"
  val transformation = "RSA"
  // ruleid: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance(transformation)
  cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
  val encryptedData = cipher.doFinal(data.getBytes())
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_7(): Unit = {
  class CryptoService {
    def encryptData(data: String, publicKey: PublicKey): Array[Byte] = {
      // ruleid: scala-rpc-ApacheXml
      val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
      cipher.init(Cipher.ENCRYPT_MODE, publicKey)
      cipher.doFinal(data.getBytes("UTF-8"))
    }
  }
  
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val service = new CryptoService()
  val encrypted = service.encryptData("Secret message", keyPair.getPublic())
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_8(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val message = "Top secret information"
  val transformations = Array("RSA", "RSA/ECB/NoPadding", "RSA/ECB/PKCS1Padding")
  
  for (transformation <- transformations) {
    // ruleid: scala-rpc-ApacheXml
    val cipher = Cipher.getInstance(transformation)
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
    val encrypted = cipher.doFinal(message.getBytes("UTF-8"))
    println(s"Encrypted with $transformation: ${Base64.getEncoder.encodeToString(encrypted)}")
  }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_9(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  def encrypt(data: String, key: PublicKey, transformation: String): String = {
    // ruleid: scala-rpc-ApacheXml
    val cipher = Cipher.getInstance(transformation)
    cipher.init(Cipher.ENCRYPT_MODE, key)
    val encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"))
    Base64.getEncoder.encodeToString(encryptedBytes)
  }
  
  val encrypted = encrypt("Sensitive data", keyPair.getPublic(), "RSA/ECB/PKCS1Padding")
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_10(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val data = "Confidential information"
  val useStrongPadding = false
  
  val transformation = if (useStrongPadding) "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING" else "RSA/ECB/PKCS1Padding"
  // ruleid: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance(transformation)
  cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
  val encrypted = cipher.doFinal(data.getBytes("UTF-8"))
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_11(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val message = "Secret message"
  val bytes = message.getBytes("UTF-8")
  
  // ruleid: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance("RSA")
  cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
  
  // Process in chunks
  val chunkSize = 100
  for (i <- 0 until bytes.length by chunkSize) {
    val end = Math.min(i + chunkSize, bytes.length)
    val chunk = bytes.slice(i, end)
    val encryptedChunk = cipher.doFinal(chunk)
    // Process encrypted chunk
  }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_12(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  trait Encryptor {
    def encrypt(data: Array[Byte], key: PublicKey): Array[Byte]
  }
  
  class RSAEncryptor extends Encryptor {
    override def encrypt(data: Array[Byte], key: PublicKey): Array[Byte] = {
      // ruleid: scala-rpc-ApacheXml
      val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
      cipher.init(Cipher.ENCRYPT_MODE, key)
      cipher.doFinal(data)
    }
  }
  
  val encryptor = new RSAEncryptor()
  val encrypted = encryptor.encrypt("Sensitive data".getBytes("UTF-8"), keyPair.getPublic())
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_13(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val config = Map(
    "algorithm" -> "RSA",
    "mode" -> "ECB",
    "padding" -> "NoPadding"
  )
  
  val transformation = s"${config("algorithm")}/${config("mode")}/${config("padding")}"
  // ruleid: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance(transformation)
  cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
  val encrypted = cipher.doFinal("Sensitive data".getBytes("UTF-8"))
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_14(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  object CryptoUtils {
    def encrypt(data: String, key: PublicKey): Array[Byte] = {
      // ruleid: scala-rpc-ApacheXml
      val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
      cipher.init(Cipher.ENCRYPT_MODE, key)
      cipher.doFinal(data.getBytes("UTF-8"))
    }
  }
  
  val encrypted = CryptoUtils.encrypt("Secret message", keyPair.getPublic())
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

def bad_case_15(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  class EncryptionService(transformation: String) {
    def encrypt(data: String, key: PublicKey): Array[Byte] = {
      // ruleid: scala-rpc-ApacheXml
      val cipher = Cipher.getInstance(transformation)
      cipher.init(Cipher.ENCRYPT_MODE, key)
      cipher.doFinal(data.getBytes("UTF-8"))
    }
  }
  
  val service = new EncryptionService("RSA")
  val encrypted = service.encrypt("Confidential data", keyPair.getPublic())
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

// True Negatives (Secure Code)

def good_case_1(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  val publicKey = keyPair.getPublic()
  
  // ok: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
  cipher.init(Cipher.ENCRYPT_MODE, publicKey)
  val plainText = "Sensitive data"
  val cipherText = cipher.doFinal(plainText.getBytes("UTF-8"))
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_2(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  val publicKey = keyPair.getPublic()
  
  // ok: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING")
  cipher.init(Cipher.ENCRYPT_MODE, publicKey)
  val plainText = "Sensitive data needs encryption"
  val cipherText = cipher.doFinal(plainText.getBytes("UTF-8"))
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_3(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  val publicKey = keyPair.getPublic()
  
  val data = "Secret message"
  // ok: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance("RSA/ECB/OAEPPADDING")
  cipher.init(Cipher.ENCRYPT_MODE, publicKey)
  val encryptedData = cipher.doFinal(data.getBytes())
  val encodedData = Base64.getEncoder.encodeToString(encryptedData)
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_4(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  val publicKey = keyPair.getPublic()
  val privateKey = keyPair.getPrivate()
  
  val message = "This is a confidential message"
  
  // ok: scala-rpc-ApacheXml
  val spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
  val encryptCipher = Cipher.getInstance("RSA/ECB/OAEPPADDING")
  encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey, spec)
  val encryptedBytes = encryptCipher.doFinal(message.getBytes(StandardCharsets.UTF_8))
  
  val decryptCipher = Cipher.getInstance("RSA/ECB/OAEPPADDING")
  decryptCipher.init(Cipher.DECRYPT_MODE, privateKey, spec)
  val decryptedBytes = decryptCipher.doFinal(encryptedBytes)
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_5(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val algorithm = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"
  // ok: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance(algorithm)
  cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
  val encrypted = cipher.doFinal("Sensitive information".getBytes("UTF-8"))
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_6(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val data = "Confidential data"
  val transformation = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"
  // ok: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance(transformation)
  cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
  val encryptedData = cipher.doFinal(data.getBytes())
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_7(): Unit = {
  class CryptoService {
    def encryptData(data: String, publicKey: PublicKey): Array[Byte] = {
      // ok: scala-rpc-ApacheXml
      val cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
      cipher.init(Cipher.ENCRYPT_MODE, publicKey)
      cipher.doFinal(data.getBytes("UTF-8"))
    }
  }
  
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val service = new CryptoService()
  val encrypted = service.encryptData("Secret message", keyPair.getPublic())
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_8(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val message = "Top secret information"
  val transformations = Array(
    "RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING",
    "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING",
    "RSA/ECB/OAEPPADDING"
  )
  
  for (transformation <- transformations) {
    // ok: scala-rpc-ApacheXml
    val cipher = Cipher.getInstance(transformation)
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
    val encrypted = cipher.doFinal(message.getBytes("UTF-8"))
    println(s"Encrypted with $transformation: ${Base64.getEncoder.encodeToString(encrypted)}")
  }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_9(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  def encrypt(data: String, key: PublicKey, transformation: String): String = {
    // ok: scala-rpc-ApacheXml
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    val encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"))
    Base64.getEncoder.encodeToString(encryptedBytes)
  }
  
  val encrypted = encrypt("Sensitive data", keyPair.getPublic(), "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_10(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val data = "Confidential information"
  val useStrongPadding = true
  
  val transformation = if (useStrongPadding) "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING" else "RSA/ECB/PKCS1Padding"
  // ok: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
  cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
  val encrypted = cipher.doFinal(data.getBytes("UTF-8"))
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_11(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val message = "Secret message"
  val bytes = message.getBytes("UTF-8")
  
  // ok: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
  cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
  
  // Process in chunks
  val chunkSize = 100
  for (i <- 0 until bytes.length by chunkSize) {
    val end = Math.min(i + chunkSize, bytes.length)
    val chunk = bytes.slice(i, end)
    val encryptedChunk = cipher.doFinal(chunk)
    // Process encrypted chunk
  }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_12(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  trait Encryptor {
    def encrypt(data: Array[Byte], key: PublicKey): Array[Byte]
  }
  
  class RSAEncryptor extends Encryptor {
    override def encrypt(data: Array[Byte], key: PublicKey): Array[Byte] = {
      // ok: scala-rpc-ApacheXml
      val cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
      cipher.init(Cipher.ENCRYPT_MODE, key)
      cipher.doFinal(data)
    }
  }
  
  val encryptor = new RSAEncryptor()
  val encrypted = encryptor.encrypt("Sensitive data".getBytes("UTF-8"), keyPair.getPublic())
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_13(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  val config = Map(
    "algorithm" -> "RSA",
    "mode" -> "ECB",
    "padding" -> "OAEPWITHSHA-256ANDMGF1PADDING"
  )
  
  val transformation = s"${config("algorithm")}/${config("mode")}/${config("padding")}"
  // ok: scala-rpc-ApacheXml
  val cipher = Cipher.getInstance(transformation)
  cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic())
  val encrypted = cipher.doFinal("Sensitive data".getBytes("UTF-8"))
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_14(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  object CryptoUtils {
    def encrypt(data: String, key: PublicKey): Array[Byte] = {
      // ok: scala-rpc-ApacheXml
      val cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
      cipher.init(Cipher.ENCRYPT_MODE, key)
      cipher.doFinal(data.getBytes("UTF-8"))
    }
  }
  
  val encrypted = CryptoUtils.encrypt("Secret message", keyPair.getPublic())
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

def good_case_15(): Unit = {
  val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
  keyPairGenerator.initialize(2048)
  val keyPair = keyPairGenerator.generateKeyPair()
  
  class EncryptionService(transformation: String) {
    def encrypt(data: String, key: PublicKey): Array[Byte] = {
      // ok: scala-rpc-ApacheXml
      val cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
      cipher.init(Cipher.ENCRYPT_MODE, key)
      cipher.doFinal(data.getBytes("UTF-8"))
    }
  }
  
  val service = new EncryptionService("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
  val encrypted = service.encrypt("Confidential data", keyPair.getPublic())
}
// {/fact}