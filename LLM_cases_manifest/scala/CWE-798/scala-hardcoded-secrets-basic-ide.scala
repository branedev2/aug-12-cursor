import java.sql.{Connection, DriverManager, Statement}
import scala.io.Source
import com.amazonaws.auth.{AWSStaticCredentialsProvider, BasicAWSCredentials}
import com.amazonaws.services.s3.AmazonS3ClientBuilder
import com.amazonaws.regions.Regions
import javax.mail.{Authenticator, PasswordAuthentication, Session}
import javax.mail.internet.{InternetAddress, MimeMessage}
import java.util.Properties
import com.mongodb.{MongoClient, MongoClientURI}
import scala.sys.process._
import java.io.File
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils
import com.azure.identity.ClientSecretCredentialBuilder
import com.azure.security.keyvault.secrets.SecretClientBuilder
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(): Unit = {
  // Database connection with hardcoded credentials
  val url = "jdbc:mysql://localhost:3306/mydb"
  val username = "admin"
  // ruleid: scala-hardcoded-secrets-basic-ide
  val password = "SuperSecretP@ssw0rd123"
  
  val connection = DriverManager.getConnection(url, username, password)
  val statement = connection.createStatement()
  statement.executeQuery("SELECT * FROM users")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_2(): Unit = {
  // AWS S3 access with hardcoded credentials
  // ruleid: scala-hardcoded-secrets-basic-ide
  val awsAccessKey = "AKIA_PLACEHOLDER_ACCESS_KEY"
  // ruleid: scala-hardcoded-secrets-basic-ide
  val awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  
  val credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey)
  val s3Client = AmazonS3ClientBuilder.standard()
    .withCredentials(new AWSStaticCredentialsProvider(credentials))
    .withRegion(Regions.US_EAST_1)
    .build()
  
  val objects = s3Client.listObjects("my-bucket")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_3(): Unit = {
  // SMTP configuration with hardcoded credentials
  val props = new Properties()
  props.put("mail.smtp.auth", "true")
  props.put("mail.smtp.starttls.enable", "true")
  props.put("mail.smtp.host", "smtp.gmail.com")
  props.put("mail.smtp.port", "587")
  
  val username = "myemail@gmail.com"
  // ruleid: scala-hardcoded-secrets-basic-ide
  val password = "gmailAppP@ssword123"
  
  val session = Session.getInstance(props, new Authenticator() {
    override protected def getPasswordAuthentication(): PasswordAuthentication = {
      new PasswordAuthentication(username, password)
    }
  })
  
  val message = new MimeMessage(session)
  message.setFrom(new InternetAddress("from@example.com"))
  message.setRecipients(javax.mail.Message.RecipientType.TO, "to@example.com")
  message.setSubject("Test Subject")
  message.setText("Test Email")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_4(): Unit = {
  // MongoDB connection with hardcoded credentials
  // ruleid: scala-hardcoded-secrets-basic-ide
  val mongoUri = "mongodb://admin:MongoDB2023P@ssword!@localhost:27017/admin"
  val client = new MongoClient(new MongoClientURI(mongoUri))
  val database = client.getDatabase("mydb")
  val collection = database.getCollection("users")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_5(): Unit = {
  // SSH connection with hardcoded password
  val host = "example.com"
  val user = "admin"
  // ruleid: scala-hardcoded-secrets-basic-ide
  val password = "SSHSecretP@ss2023!"
  
  val cmd = s"sshpass -p '$password' ssh $user@$host 'ls -la'"
  cmd.!
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_6(): Unit = {
  // API key in HTTP request
  val httpClient = HttpClients.createDefault()
  // ruleid: scala-hardcoded-secrets-basic-ide
  val apiKey = "sk_test_PLACEHOLDER_KEY"
  val request = new HttpGet(s"https://api.stripe.com/v1/charges?api_key=$apiKey")
  
  val response = httpClient.execute(request)
  val responseBody = EntityUtils.toString(response.getEntity)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_7(): Unit = {
  // Hardcoded OAuth client secret
  val clientId = "my-client-id"
  // ruleid: scala-hardcoded-secrets-basic-ide
  val clientSecret = "oauth2_client_secret_a1b2c3d4e5f6"
  
  val tokenUrl = "https://oauth.example.com/token"
  val httpClient = HttpClients.createDefault()
  val request = new HttpGet(s"$tokenUrl?client_id=$clientId&client_secret=$clientSecret&grant_type=client_credentials")
  
  val response = httpClient.execute(request)
  val responseBody = EntityUtils.toString(response.getEntity)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_8(): Unit = {
  // Azure Key Vault with hardcoded credentials
  val tenantId = "11111111-1111-1111-1111-111111111111"
  val clientId = "22222222-2222-2222-2222-222222222222"
  // ruleid: scala-hardcoded-secrets-basic-ide
  val clientSecret = "AzureKeyVaultSecret_a1b2c3d4e5f6g7h8i9j0"
  
  val credential = new ClientSecretCredentialBuilder()
    .tenantId(tenantId)
    .clientId(clientId)
    .clientSecret(clientSecret)
    .build()
  
  val client = new SecretClientBuilder()
    .vaultUrl("https://myvault.vault.azure.net/")
    .credential(credential)
    .buildClient()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_9(): Unit = {
  // Hardcoded encryption key
  // ruleid: scala-hardcoded-secrets-basic-ide
  val encryptionKey = "AES256_encryption_key_0123456789abcdef"
  
  val cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
  val keySpec = new javax.crypto.spec.SecretKeySpec(encryptionKey.getBytes(), "AES")
  cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec)
  
  val encrypted = cipher.doFinal("sensitive data".getBytes())
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_10(): Unit = {
  // Hardcoded JWT signing key
  // ruleid: scala-hardcoded-secrets-basic-ide
  val jwtSecret = "jwt_signing_secret_key_very_long_and_secure_abcdefghijklmnopqrstuvwxyz"
  
  val algorithm = io.jsonwebtoken.SignatureAlgorithm.HS256
  val jwt = io.jsonwebtoken.Jwts.builder()
    .setSubject("user123")
    .setIssuedAt(new java.util.Date())
    .signWith(algorithm, jwtSecret.getBytes())
    .compact()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_11(): Unit = {
  // Hardcoded Redis password
  val host = "redis.example.com"
  val port = 6379
  // ruleid: scala-hardcoded-secrets-basic-ide
  val password = "Redis_P@ssword_2023!"
  
  val jedis = new redis.clients.jedis.Jedis(host, port)
  jedis.auth(password)
  jedis.set("key", "value")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_12(): Unit = {
  // Hardcoded FTP credentials
  val server = "ftp.example.com"
  val user = "ftpuser"
  // ruleid: scala-hardcoded-secrets-basic-ide
  val password = "FTP_Secret_P@ssw0rd"
  
  val ftp = new org.apache.commons.net.ftp.FTPClient()
  ftp.connect(server)
  ftp.login(user, password)
  ftp.retrieveFile("remote.txt", new java.io.FileOutputStream("local.txt"))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_13(): Unit = {
  // Hardcoded credentials in configuration object
  case class DatabaseConfig(url: String, user: String, password: String)
  
  val config = DatabaseConfig(
    url = "jdbc:postgresql://localhost:5432/mydb",
    user = "postgres",
    // ruleid: scala-hardcoded-secrets-basic-ide
    password = "Postgres_Admin_P@ss"
  )
  
  val connection = DriverManager.getConnection(config.url, config.user, config.password)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_14(): Unit = {
  // Hardcoded API token in a case class
  case class ApiClient(baseUrl: String, token: String)
  
  // ruleid: scala-hardcoded-secrets-basic-ide
  val client = ApiClient("https://api.example.com", "api_token_secret_abcdef123456")
  
  val httpClient = HttpClients.createDefault()
  val request = new HttpGet(s"${client.baseUrl}/data")
  request.addHeader("Authorization", s"Bearer ${client.token}")
  
  val response = httpClient.execute(request)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_15(): Unit = {
  // Hardcoded credentials in a trait implementation
  trait Authenticator {
    def getCredentials(): (String, String)
  }
  
  class HardcodedAuthenticator extends Authenticator {
    override def getCredentials(): (String, String) = {
      val username = "admin"
      // ruleid: scala-hardcoded-secrets-basic-ide
      val password = "Super_Secret_Admin_P@ss!"
      (username, password)
    }
  }
  
  val auth = new HardcodedAuthenticator()
  val (user, pass) = auth.getCredentials()
  val connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", user, pass)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// True Negative Examples (Secure Code)

def good_case_1(): Unit = {
  // Database connection with credentials from environment variables
  val url = "jdbc:mysql://localhost:3306/mydb"
  val username = sys.env.getOrElse("DB_USERNAME", "")
  // ok: scala-hardcoded-secrets-basic-ide
  val password = sys.env.getOrElse("DB_PASSWORD", "")
  
  val connection = DriverManager.getConnection(url, username, password)
  val statement = connection.createStatement()
  statement.executeQuery("SELECT * FROM users")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_2(): Unit = {
  // AWS S3 access with credentials from environment variables
  // ok: scala-hardcoded-secrets-basic-ide
  val awsAccessKey = sys.env.getOrElse("AWS_ACCESS_KEY", "")
  val awsSecretKey = sys.env.getOrElse("AWS_SECRET_KEY", "")
  
  val credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey)
  val s3Client = AmazonS3ClientBuilder.standard()
    .withCredentials(new AWSStaticCredentialsProvider(credentials))
    .withRegion(Regions.US_EAST_1)
    .build()
  
  val objects = s3Client.listObjects("my-bucket")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_3(): Unit = {
  // SMTP configuration with credentials from configuration file
  val props = new Properties()
  props.put("mail.smtp.auth", "true")
  props.put("mail.smtp.starttls.enable", "true")
  props.put("mail.smtp.host", "smtp.gmail.com")
  props.put("mail.smtp.port", "587")
  
  // Load credentials from a properties file
  val configFile = new File("config.properties")
  val configProps = new Properties()
  configProps.load(new java.io.FileInputStream(configFile))
  
  // ok: scala-hardcoded-secrets-basic-ide
  val username = configProps.getProperty("smtp.username")
  val password = configProps.getProperty("smtp.password")
  
  val session = Session.getInstance(props, new Authenticator() {
    override protected def getPasswordAuthentication(): PasswordAuthentication = {
      new PasswordAuthentication(username, password)
    }
  })
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_4(): Unit = {
  // MongoDB connection with credentials from environment variables
  val mongoUser = sys.env.getOrElse("MONGO_USER", "")
  // ok: scala-hardcoded-secrets-basic-ide
  val mongoPass = sys.env.getOrElse("MONGO_PASS", "")
  val mongoHost = sys.env.getOrElse("MONGO_HOST", "localhost")
  val mongoPort = sys.env.getOrElse("MONGO_PORT", "27017")
  
  val mongoUri = s"mongodb://$mongoUser:$mongoPass@$mongoHost:$mongoPort/admin"
  val client = new MongoClient(new MongoClientURI(mongoUri))
  val database = client.getDatabase("mydb")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_5(): Unit = {
  // SSH connection with password from a secure source
  val host = "example.com"
  val user = "admin"
  // ok: scala-hardcoded-secrets-basic-ide
  val password = sys.env.getOrElse("SSH_PASSWORD", "")
  
  val cmd = s"sshpass -p '$password' ssh $user@$host 'ls -la'"
  cmd.!
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_6(): Unit = {
  // API key from environment variable
  val httpClient = HttpClients.createDefault()
  // ok: scala-hardcoded-secrets-basic-ide
  val apiKey = sys.env.getOrElse("STRIPE_API_KEY", "")
  val request = new HttpGet(s"https://api.stripe.com/v1/charges?api_key=$apiKey")
  
  val response = httpClient.execute(request)
  val responseBody = EntityUtils.toString(response.getEntity)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_7(): Unit = {
  // OAuth client secret from configuration
  val clientId = "my-client-id"
  // ok: scala-hardcoded-secrets-basic-ide
  val clientSecret = loadSecretFromVault("oauth_client_secret")
  
  val tokenUrl = "https://oauth.example.com/token"
  val httpClient = HttpClients.createDefault()
  val request = new HttpGet(s"$tokenUrl?client_id=$clientId&client_secret=$clientSecret&grant_type=client_credentials")
  
  val response = httpClient.execute(request)
  val responseBody = EntityUtils.toString(response.getEntity)
  
  // Helper function to load secrets from a secure vault
  def loadSecretFromVault(secretName: String): String = {
    // This would be implemented to securely retrieve secrets
    // For example, using HashiCorp Vault, AWS Secrets Manager, etc.
    sys.env.getOrElse(s"VAULT_$secretName", "")
  }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_8(): Unit = {
  // Azure Key Vault with credentials from environment
  val tenantId = sys.env.getOrElse("AZURE_TENANT_ID", "")
  val clientId = sys.env.getOrElse("AZURE_CLIENT_ID", "")
  // ok: scala-hardcoded-secrets-basic-ide
  val clientSecret = sys.env.getOrElse("AZURE_CLIENT_SECRET", "")
  
  val credential = new ClientSecretCredentialBuilder()
    .tenantId(tenantId)
    .clientId(clientId)
    .clientSecret(clientSecret)
    .build()
  
  val client = new SecretClientBuilder()
    .vaultUrl("https://myvault.vault.azure.net/")
    .credential(credential)
    .buildClient()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_9(): Unit = {
  // Encryption key from a secure source
  // ok: scala-hardcoded-secrets-basic-ide
  val encryptionKey = loadKeyFromSecureStorage("encryption_key")
  
  val cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
  val keySpec = new javax.crypto.spec.SecretKeySpec(encryptionKey.getBytes(), "AES")
  cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec)
  
  val encrypted = cipher.doFinal("sensitive data".getBytes())
  
  // Helper function to load keys from secure storage
  def loadKeyFromSecureStorage(keyName: String): String = {
    // This would be implemented to securely retrieve keys
    sys.env.getOrElse(s"SECURE_KEY_$keyName", "")
  }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_10(): Unit = {
  // JWT signing key from environment variable
  // ok: scala-hardcoded-secrets-basic-ide
  val jwtSecret = sys.env.getOrElse("JWT_SECRET_KEY", "")
  
  val algorithm = io.jsonwebtoken.SignatureAlgorithm.HS256
  val jwt = io.jsonwebtoken.Jwts.builder()
    .setSubject("user123")
    .setIssuedAt(new java.util.Date())
    .signWith(algorithm, jwtSecret.getBytes())
    .compact()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_11(): Unit = {
  // Redis password from configuration
  val config = loadConfiguration()
  val host = config.getOrElse("redis.host", "localhost")
  val port = config.getOrElse("redis.port", "6379").toInt
  // ok: scala-hardcoded-secrets-basic-ide
  val password = config.getOrElse("redis.password", "")
  
  val jedis = new redis.clients.jedis.Jedis(host, port)
  jedis.auth(password)
  jedis.set("key", "value")
  
  // Helper function to load configuration
  def loadConfiguration(): Map[String, String] = {
    // This would load configuration from a secure source
    sys.env.toMap.filter(_._1.startsWith("CONFIG_"))
      .map { case (k, v) => (k.substring(7).toLowerCase, v) }
  }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_12(): Unit = {
  // FTP credentials from a secure source
  val server = "ftp.example.com"
  val user = sys.env.getOrElse("FTP_USER", "")
  // ok: scala-hardcoded-secrets-basic-ide
  val password = sys.env.getOrElse("FTP_PASSWORD", "")
  
  val ftp = new org.apache.commons.net.ftp.FTPClient()
  ftp.connect(server)
  ftp.login(user, password)
  ftp.retrieveFile("remote.txt", new java.io.FileOutputStream("local.txt"))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_13(): Unit = {
  // Credentials in configuration object from environment
  case class DatabaseConfig(url: String, user: String, password: String)
  
  // ok: scala-hardcoded-secrets-basic-ide
  val config = DatabaseConfig(
    url = sys.env.getOrElse("DB_URL", "jdbc:postgresql://localhost:5432/mydb"),
    user = sys.env.getOrElse("DB_USER", ""),
    password = sys.env.getOrElse("DB_PASSWORD", "")
  )
  
  val connection = DriverManager.getConnection(config.url, config.user, config.password)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_14(): Unit = {
  // API token from secure storage in a case class
  case class ApiClient(baseUrl: String, token: String)
  
  // ok: scala-hardcoded-secrets-basic-ide
  val token = getSecureToken("api_service")
  val client = ApiClient("https://api.example.com", token)
  
  val httpClient = HttpClients.createDefault()
  val request = new HttpGet(s"${client.baseUrl}/data")
  request.addHeader("Authorization", s"Bearer ${client.token}")
  
  val response = httpClient.execute(request)
  
  // Helper function to get token from secure storage
  def getSecureToken(service: String): String = {
    // This would retrieve the token from a secure source
    sys.env.getOrElse(s"TOKEN_$service", "")
  }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_15(): Unit = {
  // Credentials in a trait implementation from secure source
  trait Authenticator {
    def getCredentials(): (String, String)
  }
  
  class SecureAuthenticator extends Authenticator {
    override def getCredentials(): (String, String) = {
      val username = sys.env.getOrElse("AUTH_USERNAME", "")
      // ok: scala-hardcoded-secrets-basic-ide
      val password = sys.env.getOrElse("AUTH_PASSWORD", "")
      (username, password)
    }
  }
  
  val auth = new SecureAuthenticator()
  val (user, pass) = auth.getCredentials()
  val connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", user, pass)
}
// {/fact}