import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import java.security.SecureRandom
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import java.security.spec.MGF1ParameterSpec
import java.nio.charset.StandardCharsets

object RSAPaddingExamples {

  // Helper function to generate RSA key pair
  def generateKeyPair(keySize: Int = 2048): KeyPair = {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(keySize)
    keyPairGenerator.generateKeyPair()
  }

  // True Positive Examples (Vulnerable Code)

  def bad_case_1(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Sensitive data to encrypt".getBytes(StandardCharsets.UTF_8)
    
    val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
    // ruleid: scala-rsa-no-padding
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def bad_case_2(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Secret message".getBytes(StandardCharsets.UTF_8)
    
    // ruleid: scala-rsa-no-padding
    val cipher = Cipher.getInstance("RSA/None/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def bad_case_3(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Confidential information".getBytes(StandardCharsets.UTF_8)
    
    // Using transformation string with explicit NoPadding
    // ruleid: scala-rsa-no-padding
    val cipher = Cipher.getInstance("RSA//NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def bad_case_4(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Top secret data".getBytes(StandardCharsets.UTF_8)
    
    val cipherName = "RSA/ECB/NoPadding"
    // ruleid: scala-rsa-no-padding
    val cipher = Cipher.getInstance(cipherName)
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def bad_case_5(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Private message".getBytes(StandardCharsets.UTF_8)
    
    val algorithm = "RSA"
    val mode = "ECB"
    val padding = "NoPadding"
    // ruleid: scala-rsa-no-padding
    val cipher = Cipher.getInstance(s"$algorithm/$mode/$padding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def bad_case_6(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val privateKey = keyPair.getPrivate
    val cipherText = Array[Byte](1, 2, 3, 4) // Simulated encrypted data
    
    // ruleid: scala-rsa-no-padding
    val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, privateKey)
    cipher.doFinal(cipherText)
  }

  def bad_case_7(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Sensitive data".getBytes(StandardCharsets.UTF_8)
    
    val options = Map("algorithm" -> "RSA", "mode" -> "ECB", "padding" -> "NoPadding")
    // ruleid: scala-rsa-no-padding
    val cipher = Cipher.getInstance(s"${options("algorithm")}/${options("mode")}/${options("padding")}")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def bad_case_8(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Important data".getBytes(StandardCharsets.UTF_8)
    
    def getCipherInstance(alg: String): Cipher = {
      Cipher.getInstance(alg)
    }
    
    // ruleid: scala-rsa-no-padding
    val cipher = getCipherInstance("RSA/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def bad_case_9(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Critical information".getBytes(StandardCharsets.UTF_8)
    
    val paddingOptions = List("PKCS1Padding", "OAEPPadding", "NoPadding")
    val selectedPadding = paddingOptions(2) // Selecting NoPadding
    
    // ruleid: scala-rsa-no-padding
    val cipher = Cipher.getInstance(s"RSA/ECB/$selectedPadding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def bad_case_10(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Restricted data".getBytes(StandardCharsets.UTF_8)
    
    val usePadding = false
    val padding = if (usePadding) "PKCS1Padding" else "NoPadding"
    
    // ruleid: scala-rsa-no-padding
    val cipher = Cipher.getInstance(s"RSA/ECB/$padding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def bad_case_11(): Array[Byte] = {
    class CryptoService {
      def encrypt(data: Array[Byte], key: PublicKey): Array[Byte] = {
        // ruleid: scala-rsa-no-padding
        val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.doFinal(data)
      }
    }
    
    val keyPair = generateKeyPair()
    val service = new CryptoService()
    service.encrypt("Protected content".getBytes(StandardCharsets.UTF_8), keyPair.getPublic)
  }

  def bad_case_12(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Classified information".getBytes(StandardCharsets.UTF_8)
    
    val cipherConfig = ("RSA", "ECB", "NoPadding")
    // ruleid: scala-rsa-no-padding
    val cipher = Cipher.getInstance(s"${cipherConfig._1}/${cipherConfig._2}/${cipherConfig._3}")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def bad_case_13(): Array[Byte] = {
    trait Encryptor {
      def encrypt(data: Array[Byte], key: PublicKey): Array[Byte]
    }
    
    class RSAEncryptor extends Encryptor {
      override def encrypt(data: Array[Byte], key: PublicKey): Array[Byte] = {
        // ruleid: scala-rsa-no-padding
        val cipher = Cipher.getInstance("RSA/None/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.doFinal(data)
      }
    }
    
    val keyPair = generateKeyPair()
    val encryptor = new RSAEncryptor()
    encryptor.encrypt("Secret code".getBytes(StandardCharsets.UTF_8), keyPair.getPublic)
  }

  def bad_case_14(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Confidential data".getBytes(StandardCharsets.UTF_8)
    
    val cipherAlgorithm = "RSA/ECB/NoPadding"
    try {
      // ruleid: scala-rsa-no-padding
      val cipher = Cipher.getInstance(cipherAlgorithm)
      cipher.init(Cipher.ENCRYPT_MODE, publicKey)
      cipher.doFinal(plainText)
    } catch {
      case e: Exception => throw new RuntimeException("Encryption failed", e)
    }
  }

  def bad_case_15(): Array[Byte] = {
    object CryptoUtils {
      def getEncryptionCipher(key: PublicKey): Cipher = {
        // ruleid: scala-rsa-no-padding
        val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher
      }
    }
    
    val keyPair = generateKeyPair()
    val plainText = "Sensitive information".getBytes(StandardCharsets.UTF_8)
    val cipher = CryptoUtils.getEncryptionCipher(keyPair.getPublic)
    cipher.doFinal(plainText)
  }

  // True Negative Examples (Secure Code)

  def good_case_1(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Sensitive data to encrypt".getBytes(StandardCharsets.UTF_8)
    
    // ok: scala-rsa-no-padding
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def good_case_2(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Secret message".getBytes(StandardCharsets.UTF_8)
    
    // ok: scala-rsa-no-padding
    val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def good_case_3(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Confidential information".getBytes(StandardCharsets.UTF_8)
    
    // Using OAEP with SHA-256 and MGF1
    // ok: scala-rsa-no-padding
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def good_case_4(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Top secret data".getBytes(StandardCharsets.UTF_8)
    
    // Using OAEP with explicit parameters
    // ok: scala-rsa-no-padding
    val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
    val oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", 
                                          MGF1ParameterSpec.SHA256, 
                                          PSource.PSpecified.DEFAULT)
    cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams)
    cipher.doFinal(plainText)
  }

  def good_case_5(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Private message".getBytes(StandardCharsets.UTF_8)
    
    val algorithm = "RSA"
    val mode = "ECB"
    val padding = "PKCS1Padding"
    // ok: scala-rsa-no-padding
    val cipher = Cipher.getInstance(s"$algorithm/$mode/$padding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def good_case_6(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val privateKey = keyPair.getPrivate
    val cipherText = Array[Byte](1, 2, 3, 4) // Simulated encrypted data
    
    // ok: scala-rsa-no-padding
    val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
    cipher.init(Cipher.DECRYPT_MODE, privateKey)
    cipher.doFinal(cipherText)
  }

  def good_case_7(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Sensitive data".getBytes(StandardCharsets.UTF_8)
    
    val options = Map("algorithm" -> "RSA", "mode" -> "ECB", "padding" -> "PKCS1Padding")
    // ok: scala-rsa-no-padding
    val cipher = Cipher.getInstance(s"${options("algorithm")}/${options("mode")}/${options("padding")}")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def good_case_8(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Important data".getBytes(StandardCharsets.UTF_8)
    
    def getCipherInstance(alg: String): Cipher = {
      Cipher.getInstance(alg)
    }
    
    // ok: scala-rsa-no-padding
    val cipher = getCipherInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def good_case_9(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Critical information".getBytes(StandardCharsets.UTF_8)
    
    val paddingOptions = List("PKCS1Padding", "OAEPPadding", "OAEPWithSHA-256AndMGF1Padding")
    val selectedPadding = paddingOptions(1) // Selecting OAEPPadding
    
    // ok: scala-rsa-no-padding
    val cipher = Cipher.getInstance(s"RSA/ECB/$selectedPadding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def good_case_10(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Restricted data".getBytes(StandardCharsets.UTF_8)
    
    val usePadding = true
    val padding = if (usePadding) "PKCS1Padding" else "OAEPPadding"
    
    // ok: scala-rsa-no-padding
    val cipher = Cipher.getInstance(s"RSA/ECB/$padding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def good_case_11(): Array[Byte] = {
    class SecureCryptoService {
      def encrypt(data: Array[Byte], key: PublicKey): Array[Byte] = {
        // ok: scala-rsa-no-padding
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.doFinal(data)
      }
    }
    
    val keyPair = generateKeyPair()
    val service = new SecureCryptoService()
    service.encrypt("Protected content".getBytes(StandardCharsets.UTF_8), keyPair.getPublic)
  }

  def good_case_12(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Classified information".getBytes(StandardCharsets.UTF_8)
    
    val cipherConfig = ("RSA", "ECB", "PKCS1Padding")
    // ok: scala-rsa-no-padding
    val cipher = Cipher.getInstance(s"${cipherConfig._1}/${cipherConfig._2}/${cipherConfig._3}")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    cipher.doFinal(plainText)
  }

  def good_case_13(): Array[Byte] = {
    trait SecureEncryptor {
      def encrypt(data: Array[Byte], key: PublicKey): Array[Byte]
    }
    
    class SecureRSAEncryptor extends SecureEncryptor {
      override def encrypt(data: Array[Byte], key: PublicKey): Array[Byte] = {
        // ok: scala-rsa-no-padding
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.doFinal(data)
      }
    }
    
    val keyPair = generateKeyPair()
    val encryptor = new SecureRSAEncryptor()
    encryptor.encrypt("Secret code".getBytes(StandardCharsets.UTF_8), keyPair.getPublic)
  }

  def good_case_14(): Array[Byte] = {
    val keyPair = generateKeyPair()
    val publicKey = keyPair.getPublic
    val plainText = "Confidential data".getBytes(StandardCharsets.UTF_8)
    
    val cipherAlgorithm = "RSA/ECB/PKCS1Padding"
    try {
      // ok: scala-rsa-no-padding
      val cipher = Cipher.getInstance(cipherAlgorithm)
      cipher.init(Cipher.ENCRYPT_MODE, publicKey)
      cipher.doFinal(plainText)
    } catch {
      case e: Exception => throw new RuntimeException("Encryption failed", e)
    }
  }

  def good_case_15(): Array[Byte] = {
    object SecureCryptoUtils {
      def getEncryptionCipher(key: PublicKey): Cipher = {
        // ok: scala-rsa-no-padding
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher
      }
    }
    
    val keyPair = generateKeyPair()
    val plainText = "Sensitive information".getBytes(StandardCharsets.UTF_8)
    val cipher = SecureCryptoUtils.getEncryptionCipher(keyPair.getPublic)
    cipher.doFinal(plainText)
  }
}