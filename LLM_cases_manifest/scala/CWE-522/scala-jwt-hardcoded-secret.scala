import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim}
import java.time.Instant
import scala.util.{Success, Failure}
import scala.io.Source
import java.nio.file.{Files, Paths}
import java.util.Properties
import com.typesafe.config.ConfigFactory
import scala.sys.env
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(): Unit = {
  // Using a hardcoded JWT secret for token generation
  val claim = JwtClaim(
    expiration = Some(Instant.now.plusSeconds(157784760).getEpochSecond),
    issuedAt = Some(Instant.now.getEpochSecond)
  )
  // ruleid: scala-jwt-hardcoded-secret
  val token = Jwt.encode(claim, "my-super-secret-key-12345", JwtAlgorithm.HS256)
  println(s"Generated token: $token")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_2(): Unit = {
  // Using a hardcoded JWT secret stored in a constant
  val claim = JwtClaim(subject = Some("user123"))
  // ruleid: scala-jwt-hardcoded-secret
  val SECRET_KEY = "this-is-my-secret-key-for-jwt-tokens"
  val token = Jwt.encode(claim, SECRET_KEY, JwtAlgorithm.HS256)
  validateToken(token, SECRET_KEY)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_3(): Unit = {
  // Using a hardcoded JWT secret for token validation
  val token = getTokenFromRequest()
  // ruleid: scala-jwt-hardcoded-secret
  Jwt.decode(token, "hardcoded-jwt-secret-key-value", Seq(JwtAlgorithm.HS256)) match {
    case Success(claim) => println(s"Token is valid: $claim")
    case Failure(ex) => println(s"Token validation failed: ${ex.getMessage}")
  }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_4(): Unit = {
  // Using a hardcoded JWT secret in a class field
  class JwtService {
    // ruleid: scala-jwt-hardcoded-secret
    private val jwtSecret = "jwt-secret-for-authentication-service"
    
    def createToken(userId: String): String = {
      val claim = JwtClaim(
        content = s"""{"user_id":"$userId"}""",
        expiration = Some(Instant.now.plusSeconds(3600).getEpochSecond)
      )
      Jwt.encode(claim, jwtSecret, JwtAlgorithm.HS256)
    }
  }
  
  val service = new JwtService()
  val token = service.createToken("user456")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_5(): Unit = {
  // Using a hardcoded JWT secret in a case class
  case class AuthConfig(
    // ruleid: scala-jwt-hardcoded-secret
    jwtSecret: String = "my-jwt-secret-for-auth-config",
    expirySeconds: Long = 3600
  )
  
  val config = AuthConfig()
  val token = Jwt.encode(JwtClaim(), config.jwtSecret, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_6(): Unit = {
  // Using a hardcoded JWT secret in a function with conditional logic
  def generateToken(userId: String, isAdmin: Boolean): String = {
    val claim = JwtClaim(
      content = s"""{"user_id":"$userId","is_admin":$isAdmin}""",
      expiration = Some(Instant.now.plusSeconds(3600).getEpochSecond)
    )
    
    val secretKey = if (isAdmin) {
      // ruleid: scala-jwt-hardcoded-secret
      "admin-jwt-secret-key-12345"
    } else {
      // ruleid: scala-jwt-hardcoded-secret
      "user-jwt-secret-key-67890"
    }
    
    Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
  }
  
  val userToken = generateToken("user789", false)
  val adminToken = generateToken("admin123", true)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_7(): Unit = {
  // Using a hardcoded JWT secret in a trait implementation
  trait TokenGenerator {
    def generateToken(userId: String): String
  }
  
  class JwtTokenGenerator extends TokenGenerator {
    // ruleid: scala-jwt-hardcoded-secret
    private val secretKey = "jwt-secret-for-token-generator-impl"
    
    override def generateToken(userId: String): String = {
      val claim = JwtClaim(
        content = s"""{"user_id":"$userId"}""",
        expiration = Some(Instant.now.plusSeconds(3600).getEpochSecond)
      )
      Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
    }
  }
  
  val generator = new JwtTokenGenerator()
  val token = generator.generateToken("user101")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_8(): Unit = {
  // Using multiple hardcoded JWT secrets for different environments
  val env = "development" // Could be "production", "staging", etc.
  
  val secretKey = env match {
    case "development" =>
      // ruleid: scala-jwt-hardcoded-secret
      "dev-environment-jwt-secret-key"
    case "staging" =>
      // ruleid: scala-jwt-hardcoded-secret
      "staging-environment-jwt-secret-key"
    case "production" =>
      // ruleid: scala-jwt-hardcoded-secret
      "production-environment-jwt-secret-key"
    case _ =>
      // ruleid: scala-jwt-hardcoded-secret
      "default-jwt-secret-key"
  }
  
  val claim = JwtClaim(subject = Some("app"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_9(): Unit = {
  // Using a hardcoded JWT secret with string concatenation
  val appName = "myapp"
  // ruleid: scala-jwt-hardcoded-secret
  val secretKey = s"${appName}-jwt-secret-key-12345"
  
  val claim = JwtClaim(
    content = """{"action":"login"}""",
    expiration = Some(Instant.now.plusSeconds(3600).getEpochSecond)
  )
  
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_10(): Unit = {
  // Using a hardcoded JWT secret in a map of configurations
  val configs = Map(
    "dbUrl" -> "jdbc:postgresql://localhost:5432/mydb",
    "dbUser" -> "admin",
    // ruleid: scala-jwt-hardcoded-secret
    "jwtSecret" -> "map-stored-jwt-secret-key-value",
    "apiUrl" -> "https://api.example.com"
  )
  
  val claim = JwtClaim(subject = Some("service"))
  val token = Jwt.encode(claim, configs("jwtSecret"), JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_11(): Unit = {
  // Using a hardcoded JWT secret in a lazy val
  // ruleid: scala-jwt-hardcoded-secret
  lazy val jwtSecret = "lazy-initialized-jwt-secret-key"
  
  def verifyToken(token: String): Boolean = {
    Jwt.isValid(token, jwtSecret, Seq(JwtAlgorithm.HS256))
  }
  
  val token = Jwt.encode(JwtClaim(), jwtSecret, JwtAlgorithm.HS256)
  val isValid = verifyToken(token)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_12(): Unit = {
  // Using a hardcoded JWT secret with multiple algorithms
  // ruleid: scala-jwt-hardcoded-secret
  val secretKey = "multi-algorithm-jwt-secret-key"
  val claim = JwtClaim(subject = Some("multi-algo"))
  
  val hs256Token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
  val hs384Token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS384)
  val hs512Token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS512)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_13(): Unit = {
  // Using a hardcoded JWT secret in an object
  object JwtHelper {
    // ruleid: scala-jwt-hardcoded-secret
    val SECRET_KEY = "object-defined-jwt-secret-key"
    
    def createToken(subject: String): String = {
      val claim = JwtClaim(
        subject = Some(subject),
        expiration = Some(Instant.now.plusSeconds(3600).getEpochSecond)
      )
      Jwt.encode(claim, SECRET_KEY, JwtAlgorithm.HS256)
    }
  }
  
  val token = JwtHelper.createToken("user123")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_14(): Unit = {
  // Using a hardcoded JWT secret with Base64 encoding
  import java.util.Base64
  
  // ruleid: scala-jwt-hardcoded-secret
  val rawSecret = "base64-encoded-jwt-secret"
  val encodedSecret = Base64.getEncoder.encodeToString(rawSecret.getBytes)
  
  val claim = JwtClaim(subject = Some("encoded"))
  val token = Jwt.encode(claim, encodedSecret, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_15(): Unit = {
  // Using a hardcoded JWT secret in a function that combines multiple secrets
  def combineSecrets(): String = {
    // ruleid: scala-jwt-hardcoded-secret
    val secret1 = "part1-of-jwt-secret"
    // ruleid: scala-jwt-hardcoded-secret
    val secret2 = "part2-of-jwt-secret"
    s"$secret1-$secret2"
  }
  
  val secretKey = combineSecrets()
  val claim = JwtClaim(subject = Some("combined"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// True Negative Examples (Secure Code)

def good_case_1(): Unit = {
  // Using environment variable for JWT secret
  val claim = JwtClaim(
    expiration = Some(Instant.now.plusSeconds(157784760).getEpochSecond),
    issuedAt = Some(Instant.now.getEpochSecond)
  )
  // ok: scala-jwt-hardcoded-secret
  val secretKey = sys.env.getOrElse("JWT_SECRET_KEY", throw new Exception("JWT secret not configured"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
  println(s"Generated token: $token")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_2(): Unit = {
  // Reading JWT secret from a configuration file
  val config = ConfigFactory.load()
  // ok: scala-jwt-hardcoded-secret
  val secretKey = config.getString("jwt.secret")
  
  val claim = JwtClaim(subject = Some("user123"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_3(): Unit = {
  // Using a secret manager service to retrieve JWT secret
  class SecretManager {
    def getSecret(name: String): String = {
      // This would actually call a secure secret management service
      // Implementation omitted for brevity
      sys.env.getOrElse(name, throw new Exception(s"Secret $name not found"))
    }
  }
  
  val secretManager = new SecretManager()
  // ok: scala-jwt-hardcoded-secret
  val jwtSecret = secretManager.getSecret("JWT_SECRET")
  
  val claim = JwtClaim()
  val token = Jwt.encode(claim, jwtSecret, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_4(): Unit = {
  // Reading JWT secret from a properties file
  def loadProperties(filename: String): Properties = {
    val properties = new Properties()
    val inputStream = getClass.getClassLoader.getResourceAsStream(filename)
    properties.load(inputStream)
    inputStream.close()
    properties
  }
  
  val props = loadProperties("config.properties")
  // ok: scala-jwt-hardcoded-secret
  val secretKey = props.getProperty("jwt.secret")
  
  val claim = JwtClaim(subject = Some("user456"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_5(): Unit = {
  // Using a function parameter for JWT secret
  def generateToken(userId: String, secretKey: String): String = {
    val claim = JwtClaim(
      content = s"""{"user_id":"$userId"}""",
      expiration = Some(Instant.now.plusSeconds(3600).getEpochSecond)
    )
    // ok: scala-jwt-hardcoded-secret
    Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
  }
  
  // Secret is passed as a parameter, not hardcoded
  val secretFromEnv = sys.env.getOrElse("JWT_SECRET", "")
  val token = generateToken("user789", secretFromEnv)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_6(): Unit = {
  // Using a secure configuration class for JWT settings
  case class JwtConfig(secretKey: String, expirySeconds: Long)
  
  def loadJwtConfig(): JwtConfig = {
    // ok: scala-jwt-hardcoded-secret
    val secretKey = sys.env.getOrElse("JWT_SECRET", "")
    val expirySeconds = sys.env.getOrElse("JWT_EXPIRY_SECONDS", "3600").toLong
    JwtConfig(secretKey, expirySeconds)
  }
  
  val config = loadJwtConfig()
  val claim = JwtClaim(
    expiration = Some(Instant.now.plusSeconds(config.expirySeconds).getEpochSecond)
  )
  val token = Jwt.encode(claim, config.secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_7(): Unit = {
  // Using a trait with secure secret retrieval
  trait SecretProvider {
    def getJwtSecret(): String
  }
  
  class EnvironmentSecretProvider extends SecretProvider {
    override def getJwtSecret(): String = {
      // ok: scala-jwt-hardcoded-secret
      sys.env.getOrElse("JWT_SECRET", throw new Exception("JWT secret not configured"))
    }
  }
  
  val provider = new EnvironmentSecretProvider()
  val secretKey = provider.getJwtSecret()
  
  val claim = JwtClaim(subject = Some("secure"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_8(): Unit = {
  // Reading JWT secret from a secure file
  def readSecretFromFile(path: String): String = {
    // ok: scala-jwt-hardcoded-secret
    new String(Files.readAllBytes(Paths.get(path))).trim
  }
  
  val secretFilePath = sys.env.getOrElse("JWT_SECRET_FILE", "/run/secrets/jwt_secret")
  val secretKey = readSecretFromFile(secretFilePath)
  
  val claim = JwtClaim(subject = Some("file-based"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_9(): Unit = {
  // Using different environment variables for different environments
  val env = sys.env.getOrElse("APP_ENV", "development")
  
  val secretKey = env match {
    case "development" =>
      // ok: scala-jwt-hardcoded-secret
      sys.env.getOrElse("DEV_JWT_SECRET", "")
    case "staging" =>
      // ok: scala-jwt-hardcoded-secret
      sys.env.getOrElse("STAGING_JWT_SECRET", "")
    case "production" =>
      // ok: scala-jwt-hardcoded-secret
      sys.env.getOrElse("PROD_JWT_SECRET", "")
    case _ =>
      // ok: scala-jwt-hardcoded-secret
      sys.env.getOrElse("JWT_SECRET", "")
  }
  
  val claim = JwtClaim(subject = Some("env-specific"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_10(): Unit = {
  // Using a secure configuration object with lazy loading
  object SecureConfig {
    // ok: scala-jwt-hardcoded-secret
    lazy val jwtSecret: String = {
      val config = ConfigFactory.load()
      config.getString("jwt.secret")
    }
  }
  
  val claim = JwtClaim(subject = Some("lazy-loaded"))
  val token = Jwt.encode(claim, SecureConfig.jwtSecret, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_11(): Unit = {
  // Using a database to store and retrieve the JWT secret
  class SecretRepository {
    def getJwtSecret(): String = {
      // This would actually query a database
      // Implementation omitted for brevity
      // ok: scala-jwt-hardcoded-secret
      sys.env.getOrElse("JWT_SECRET", "")
    }
  }
  
  val repo = new SecretRepository()
  val secretKey = repo.getJwtSecret()
  
  val claim = JwtClaim(subject = Some("db-stored"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_12(): Unit = {
  // Using a secure vault service for JWT secret
  trait VaultService {
    def getSecret(path: String): String
  }
  
  class HashiCorpVaultService extends VaultService {
    override def getSecret(path: String): String = {
      // This would actually call HashiCorp Vault API
      // Implementation omitted for brevity
      // ok: scala-jwt-hardcoded-secret
      sys.env.getOrElse("VAULT_" + path.toUpperCase.replace('/', '_'), "")
    }
  }
  
  val vaultService = new HashiCorpVaultService()
  val secretKey = vaultService.getSecret("secrets/jwt/key")
  
  val claim = JwtClaim(subject = Some("vault-stored"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_13(): Unit = {
  // Using a function to generate a secure random JWT secret
  import java.security.SecureRandom
  import java.util.Base64
  
  def generateSecureSecret(length: Int): String = {
    val random = new SecureRandom()
    val bytes = new Array[Byte](length)
    random.nextBytes(bytes)
    Base64.getEncoder.encodeToString(bytes)
  }
  
  // ok: scala-jwt-hardcoded-secret
  val secretKey = sys.env.getOrElse("JWT_SECRET", generateSecureSecret(32))
  
  val claim = JwtClaim(subject = Some("generated"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_14(): Unit = {
  // Using AWS Secrets Manager to retrieve JWT secret
  class AwsSecretsManager {
    def getSecret(secretName: String): String = {
      // This would actually call AWS Secrets Manager API
      // Implementation omitted for brevity
      // ok: scala-jwt-hardcoded-secret
      sys.env.getOrElse("AWS_SECRET_" + secretName.toUpperCase, "")
    }
  }
  
  val secretsManager = new AwsSecretsManager()
  val secretKey = secretsManager.getSecret("jwt_secret")
  
  val claim = JwtClaim(subject = Some("aws-stored"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_15(): Unit = {
  // Using a secure configuration with fallback mechanism
  def getJwtSecret(): String = {
    // Try environment variable first
    sys.env.get("JWT_SECRET").orElse {
      // Then try system property
      Option(System.getProperty("jwt.secret"))
    }.orElse {
      // Then try config file
      try {
        val config = ConfigFactory.load()
        Some(config.getString("jwt.secret"))
      } catch {
        case _: Exception => None
      }
    }.getOrElse {
      // Finally, fail if no secret is available
      throw new Exception("JWT secret not configured")
    }
  }
  
  // ok: scala-jwt-hardcoded-secret
  val secretKey = getJwtSecret()
  
  val claim = JwtClaim(subject = Some("fallback"))
  val token = Jwt.encode(claim, secretKey, JwtAlgorithm.HS256)
}
// {/fact}

// Helper functions
def getTokenFromRequest(): String = {
  // This would actually get the token from an HTTP request
  // Implementation omitted for brevity
  ""
}

def validateToken(token: String, secret: String): Boolean = {
  Jwt.isValid(token, secret, Seq(JwtAlgorithm.HS256))
}