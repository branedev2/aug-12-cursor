import com.hazelcast.config.{Config, SymmetricEncryptionConfig}
import com.hazelcast.core.{Hazelcast, HazelcastInstance}
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Base64
import scala.util.Random
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // ruleid: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("DES") // Weak encryption algorithm
  encryptionConfig.setSalt("somesalt")
  encryptionConfig.setPassword("password123")
  encryptionConfig.setIterationCount(10)
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_2(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // ruleid: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  encryptionConfig.setSalt("fixedsalt")
  encryptionConfig.setPassword("mypassword")
  encryptionConfig.setIterationCount(50) // Insufficient iteration count
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_3(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // ruleid: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("Blowfish") // Weak algorithm
  encryptionConfig.setSalt("salt12345")
  encryptionConfig.setPassword("hazelcast-password")
  encryptionConfig.setIterationCount(1000) // Still insufficient
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_4(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // ruleid: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("RC4") // Very weak algorithm
  encryptionConfig.setSalt("randomsalt")
  encryptionConfig.setPassword("strongpassword123!")
  encryptionConfig.setIterationCount(5000)
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_5(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // ruleid: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  encryptionConfig.setSalt("salt")
  encryptionConfig.setPassword("password") // Weak password
  encryptionConfig.setIterationCount(10000) // Still below recommended 100,000
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_6(): Unit = {
  val config = new Config()
  
  // Creating encryption config with weak settings
  val encryptionConfig = new SymmetricEncryptionConfig()
  // ruleid: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("3DES") // Weak algorithm
  encryptionConfig.setSalt("saltsaltsalt")
  encryptionConfig.setPassword("hazelcast")
  encryptionConfig.setIterationCount(20000)
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val instance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_7(): Unit = {
  // Creating a cluster with weak encryption
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // ruleid: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  encryptionConfig.setSalt("static-salt-value")
  encryptionConfig.setPassword("cluster-password")
  encryptionConfig.setIterationCount(1) // Extremely low iteration count
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_8(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // ruleid: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("DESede") // Triple DES, still weak
  encryptionConfig.setSalt("hazelcast-salt")
  encryptionConfig.setPassword("hazelcast-password")
  encryptionConfig.setIterationCount(30000) // Below recommended
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_9(): Unit = {
  // Setting up a development cluster with weak encryption
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // ruleid: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  encryptionConfig.setSalt("dev-salt")
  encryptionConfig.setPassword("dev-password")
  encryptionConfig.setIterationCount(500) // Very low for development
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_10(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // ruleid: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("RC2") // Very weak algorithm
  encryptionConfig.setSalt("test-salt")
  encryptionConfig.setPassword("test-password")
  encryptionConfig.setIterationCount(15000)
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_11(): Unit = {
  // Creating a config with weak settings in a factory method
  val config = createWeakConfig()
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  def createWeakConfig(): Config = {
    val config = new Config()
    val encryptionConfig = new SymmetricEncryptionConfig()
    
    // ruleid: scala-hazelcast-symmetric-encryption
    encryptionConfig.setAlgorithm("AES")
    encryptionConfig.setSalt("factory-salt")
    encryptionConfig.setPassword("factory-password")
    encryptionConfig.setIterationCount(25000) // Still below recommended
    
    config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
    config
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_12(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  val algorithm = "AES"
  val salt = "configurable-salt"
  val password = "configurable-password"
  val iterations = 50000 // Below recommended
  
  // ruleid: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm(algorithm)
  encryptionConfig.setSalt(salt)
  encryptionConfig.setPassword(password)
  encryptionConfig.setIterationCount(iterations)
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_13(): Unit = {
  // Using a builder pattern with weak settings
  val hazelcastInstance = createHazelcastInstance("AES", "builder-salt", "builder-password", 75000) // Below recommended
  
  def createHazelcastInstance(algorithm: String, salt: String, password: String, iterations: Int): HazelcastInstance = {
    val config = new Config()
    val encryptionConfig = new SymmetricEncryptionConfig()
    
    // ruleid: scala-hazelcast-symmetric-encryption
    encryptionConfig.setAlgorithm(algorithm)
    encryptionConfig.setSalt(salt)
    encryptionConfig.setPassword(password)
    encryptionConfig.setIterationCount(iterations)
    
    config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
    Hazelcast.newHazelcastInstance(config)
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_14(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // ruleid: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  // Using empty salt - very insecure
  encryptionConfig.setSalt("")
  encryptionConfig.setPassword("password123")
  encryptionConfig.setIterationCount(90000) // Close but still below recommended
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_15(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // Conditionally setting weak encryption
  val isDevEnvironment = true
  
  if (isDevEnvironment) {
    // ruleid: scala-hazelcast-symmetric-encryption
    encryptionConfig.setAlgorithm("AES")
    encryptionConfig.setSalt("dev-environment-salt")
    encryptionConfig.setPassword("dev-password")
    encryptionConfig.setIterationCount(1000) // Very low for development
  } else {
    encryptionConfig.setAlgorithm("AES")
    encryptionConfig.setSalt(generateSecureSalt())
    encryptionConfig.setPassword(generateSecurePassword())
    encryptionConfig.setIterationCount(100000)
  }
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  def generateSecureSalt(): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](16)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
  
  def generateSecurePassword(): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](24)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// True Negative Examples (Secure Code)

def good_case_1(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // ok: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  encryptionConfig.setSalt(generateSecureSalt())
  encryptionConfig.setPassword(generateSecurePassword())
  encryptionConfig.setIterationCount(100000) // Recommended minimum
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  def generateSecureSalt(): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](16)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
  
  def generateSecurePassword(): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](24)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_2(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // ok: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  encryptionConfig.setSalt("securely-generated-salt-value-123456789")
  encryptionConfig.setPassword("strong-password-generated-securely-123456789")
  encryptionConfig.setIterationCount(150000) // Above recommended minimum
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_3(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  val secureRandom = new SecureRandom()
  val saltBytes = new Array[Byte](16)
  secureRandom.nextBytes(saltBytes)
  val salt = Base64.encodeBase64String(saltBytes)
  
  val passwordBytes = new Array[Byte](32)
  secureRandom.nextBytes(passwordBytes)
  val password = Base64.encodeBase64String(passwordBytes)
  
  // ok: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  encryptionConfig.setSalt(salt)
  encryptionConfig.setPassword(password)
  encryptionConfig.setIterationCount(200000) // Well above recommended minimum
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_4(): Unit = {
  // Using environment variables for secure configuration
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  val algorithm = System.getenv().getOrDefault("HZ_ENCRYPTION_ALGORITHM", "AES")
  val salt = System.getenv().getOrDefault("HZ_ENCRYPTION_SALT", generateSecureSalt())
  val password = System.getenv().getOrDefault("HZ_ENCRYPTION_PASSWORD", generateSecurePassword())
  val iterations = Integer.parseInt(System.getenv().getOrDefault("HZ_ENCRYPTION_ITERATIONS", "100000"))
  
  // ok: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm(algorithm)
  encryptionConfig.setSalt(salt)
  encryptionConfig.setPassword(password)
  encryptionConfig.setIterationCount(iterations)
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  def generateSecureSalt(): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](16)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
  
  def generateSecurePassword(): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](24)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_5(): Unit = {
  val config = new Config()
  
  // Using a factory method for secure configuration
  val encryptionConfig = createSecureEncryptionConfig()
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  def createSecureEncryptionConfig(): SymmetricEncryptionConfig = {
    val encryptionConfig = new SymmetricEncryptionConfig()
    
    // ok: scala-hazelcast-symmetric-encryption
    encryptionConfig.setAlgorithm("AES")
    encryptionConfig.setSalt(generateRandomString(32))
    encryptionConfig.setPassword(generateRandomString(32))
    encryptionConfig.setIterationCount(250000) // Well above recommended
    
    encryptionConfig
  }
  
  def generateRandomString(length: Int): String = {
    val random = new SecureRandom()
    val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+"
    val sb = new StringBuilder(length)
    for (_ <- 0 until length) {
      sb.append(chars.charAt(random.nextInt(chars.length())))
    }
    sb.toString()
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_6(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // Using a stronger algorithm with good parameters
  // ok: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  encryptionConfig.setSalt(generateSecureSalt(32)) // 32 bytes salt
  encryptionConfig.setPassword(generateSecurePassword(32)) // 32 bytes password
  encryptionConfig.setIterationCount(500000) // Very high iteration count
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  def generateSecureSalt(length: Int): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](length)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
  
  def generateSecurePassword(length: Int): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](length)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_7(): Unit = {
  // Creating a secure Hazelcast instance with proper encryption
  val hazelcastInstance = createSecureHazelcastInstance()
  
  def createSecureHazelcastInstance(): HazelcastInstance = {
    val config = new Config()
    val encryptionConfig = new SymmetricEncryptionConfig()
    
    // ok: scala-hazelcast-symmetric-encryption
    encryptionConfig.setAlgorithm("AES")
    encryptionConfig.setSalt(generateRandomSalt())
    encryptionConfig.setPassword(generateStrongPassword())
    encryptionConfig.setIterationCount(100000) // Meets recommended minimum
    
    config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
    Hazelcast.newHazelcastInstance(config)
  }
  
  def generateRandomSalt(): String = {
    val random = new SecureRandom()
    val saltBytes = new Array[Byte](16)
    random.nextBytes(saltBytes)
    Base64.encodeBase64String(saltBytes)
  }
  
  def generateStrongPassword(): String = {
    val random = new SecureRandom()
    val passwordBytes = new Array[Byte](32)
    random.nextBytes(passwordBytes)
    Base64.encodeBase64String(passwordBytes)
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_8(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // Using a configuration class to manage secure settings
  val securityConfig = new SecurityConfiguration()
  
  // ok: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm(securityConfig.getEncryptionAlgorithm())
  encryptionConfig.setSalt(securityConfig.getEncryptionSalt())
  encryptionConfig.setPassword(securityConfig.getEncryptionPassword())
  encryptionConfig.setIterationCount(securityConfig.getEncryptionIterationCount())
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  class SecurityConfiguration {
    private val secureRandom = new SecureRandom()
    
    def getEncryptionAlgorithm(): String = "AES"
    
    def getEncryptionSalt(): String = {
      val saltBytes = new Array[Byte](16)
      secureRandom.nextBytes(saltBytes)
      Base64.encodeBase64String(saltBytes)
    }
    
    def getEncryptionPassword(): String = {
      val passwordBytes = new Array[Byte](32)
      secureRandom.nextBytes(passwordBytes)
      Base64.encodeBase64String(passwordBytes)
    }
    
    def getEncryptionIterationCount(): Int = 150000 // Above recommended minimum
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_9(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // Using a secure key generator
  val keyGenerator = new SecureKeyGenerator()
  
  // ok: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  encryptionConfig.setSalt(keyGenerator.generateSalt())
  encryptionConfig.setPassword(keyGenerator.generatePassword())
  encryptionConfig.setIterationCount(300000) // Well above recommended minimum
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  class SecureKeyGenerator {
    private val secureRandom = new SecureRandom()
    
    def generateSalt(): String = {
      val saltBytes = new Array[Byte](32)
      secureRandom.nextBytes(saltBytes)
      Base64.encodeBase64String(saltBytes)
    }
    
    def generatePassword(): String = {
      val passwordBytes = new Array[Byte](32)
      secureRandom.nextBytes(passwordBytes)
      Base64.encodeBase64String(passwordBytes)
    }
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_10(): Unit = {
  // Conditionally setting secure encryption based on environment
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  val isProduction = true
  
  if (isProduction) {
    // ok: scala-hazelcast-symmetric-encryption
    encryptionConfig.setAlgorithm("AES")
    encryptionConfig.setSalt(generateSecureSalt())
    encryptionConfig.setPassword(generateSecurePassword())
    encryptionConfig.setIterationCount(200000) // Well above recommended minimum
  } else {
    // Even in development, we use secure settings
    encryptionConfig.setAlgorithm("AES")
    encryptionConfig.setSalt(generateSecureSalt())
    encryptionConfig.setPassword(generateSecurePassword())
    encryptionConfig.setIterationCount(100000) // Meets recommended minimum
  }
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  def generateSecureSalt(): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](16)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
  
  def generateSecurePassword(): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](24)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_11(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // Using a secure configuration builder
  val secureConfigBuilder = new SecureConfigBuilder()
  secureConfigBuilder.configureEncryption(encryptionConfig)
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  class SecureConfigBuilder {
    def configureEncryption(config: SymmetricEncryptionConfig): Unit = {
      val secureRandom = new SecureRandom()
      
      val saltBytes = new Array[Byte](32)
      secureRandom.nextBytes(saltBytes)
      val salt = Base64.encodeBase64String(saltBytes)
      
      val passwordBytes = new Array[Byte](32)
      secureRandom.nextBytes(passwordBytes)
      val password = Base64.encodeBase64String(passwordBytes)
      
      // ok: scala-hazelcast-symmetric-encryption
      config.setAlgorithm("AES")
      config.setSalt(salt)
      config.setPassword(password)
      config.setIterationCount(150000) // Above recommended minimum
    }
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_12(): Unit = {
  // Using a secure configuration from a properties file
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // Simulating properties loaded from a secure source
  val properties = new java.util.Properties()
  properties.setProperty("encryption.algorithm", "AES")
  properties.setProperty("encryption.salt", generateSecureSalt())
  properties.setProperty("encryption.password", generateSecurePassword())
  properties.setProperty("encryption.iterations", "200000")
  
  // ok: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm(properties.getProperty("encryption.algorithm"))
  encryptionConfig.setSalt(properties.getProperty("encryption.salt"))
  encryptionConfig.setPassword(properties.getProperty("encryption.password"))
  encryptionConfig.setIterationCount(Integer.parseInt(properties.getProperty("encryption.iterations")))
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  def generateSecureSalt(): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](16)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
  
  def generateSecurePassword(): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](24)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_13(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // Using a secure key management service (simulated)
  val keyManagementService = new KeyManagementService()
  val encryptionKey = keyManagementService.getEncryptionKey("hazelcast-cluster")
  
  // ok: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  encryptionConfig.setSalt(encryptionKey.getSalt())
  encryptionConfig.setPassword(encryptionKey.getPassword())
  encryptionConfig.setIterationCount(encryptionKey.getIterationCount()) // Service ensures this is at least 100,000
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  class KeyManagementService {
    def getEncryptionKey(keyName: String): EncryptionKey = {
      // In a real implementation, this would retrieve keys from a secure vault
      val secureRandom = new SecureRandom()
      
      val saltBytes = new Array[Byte](32)
      secureRandom.nextBytes(saltBytes)
      val salt = Base64.encodeBase64String(saltBytes)
      
      val passwordBytes = new Array[Byte](32)
      secureRandom.nextBytes(passwordBytes)
      val password = Base64.encodeBase64String(passwordBytes)
      
      new EncryptionKey(salt, password, 250000)
    }
  }
  
  class EncryptionKey(private val salt: String, private val password: String, private val iterationCount: Int) {
    def getSalt(): String = salt
    def getPassword(): String = password
    def getIterationCount(): Int = iterationCount
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_14(): Unit = {
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // Using a secure random generator with sufficient entropy
  val secureRandom = new SecureRandom()
  secureRandom.setSeed(System.nanoTime()) // Additional entropy
  
  val saltBytes = new Array[Byte](32)
  secureRandom.nextBytes(saltBytes)
  val salt = Base64.encodeBase64String(saltBytes)
  
  val passwordBytes = new Array[Byte](32)
  secureRandom.nextBytes(passwordBytes)
  val password = Base64.encodeBase64String(passwordBytes)
  
  // ok: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  encryptionConfig.setSalt(salt)
  encryptionConfig.setPassword(password)
  encryptionConfig.setIterationCount(500000) // Very high iteration count
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_15(): Unit = {
  // Using a secure configuration with proper key length
  val config = new Config()
  val encryptionConfig = new SymmetricEncryptionConfig()
  
  // Generate a secure 256-bit key (32 bytes)
  val keyBytes = new Array[Byte](32)
  new SecureRandom().nextBytes(keyBytes)
  val keySpec = new SecretKeySpec(keyBytes, "AES")
  
  // ok: scala-hazelcast-symmetric-encryption
  encryptionConfig.setAlgorithm("AES")
  encryptionConfig.setSalt(generateSecureSalt(32))
  encryptionConfig.setPassword(Base64.encodeBase64String(keyBytes))
  encryptionConfig.setIterationCount(200000) // Well above recommended minimum
  
  config.getNetworkConfig().setSymmetricEncryption(encryptionConfig)
  val hazelcastInstance = Hazelcast.newHazelcastInstance(config)
  
  def generateSecureSalt(length: Int): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](length)
    random.nextBytes(bytes)
    Base64.encodeBase64String(bytes)
  }
}
// {/fact}