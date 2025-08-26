import scala.io.Source
import java.sql.{Connection, DriverManager}
import com.amazonaws.auth.{AWSStaticCredentialsProvider, BasicAWSCredentials}
import com.amazonaws.services.s3.AmazonS3ClientBuilder
import javax.mail.{Authenticator, PasswordAuthentication, Session}
import java.util.Properties
import scala.sys.process._
import com.mongodb.{MongoClient, MongoClientURI}
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils
import java.io.File
import scala.util.Properties.envOrElse
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(): Unit = {
  // Database connection with hardcoded credentials
  val dbUrl = "jdbc:mysql://localhost:3306/mydb"
  val username = "admin"
  // ruleid: scala-hardcoded-credentials-library-ide
  val password = "Password123!"
  
  val connection = DriverManager.getConnection(dbUrl, username, password)
  // Use connection for database operations
  connection.close()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_2(): Unit = {
  // AWS S3 access with hardcoded credentials
  // ruleid: scala-hardcoded-credentials-library-ide
  val awsAccessKey = "AKIA_PLACEHOLDER_ACCESS_KEY"
  // ruleid: scala-hardcoded-credentials-library-ide
  val awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  
  val credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey)
  val s3Client = AmazonS3ClientBuilder.standard()
    .withCredentials(new AWSStaticCredentialsProvider(credentials))
    .withRegion("us-west-2")
    .build()
    
  val objects = s3Client.listObjects("my-bucket")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_3(): Unit = {
  // SMTP configuration with hardcoded credentials
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.gmail.com")
  props.put("mail.smtp.port", "587")
  props.put("mail.smtp.auth", "true")
  props.put("mail.smtp.starttls.enable", "true")
  
  val username = "myemail@gmail.com"
  // ruleid: scala-hardcoded-credentials-library-ide
  val password = "myGmailP@ssw0rd"
  
  val session = Session.getInstance(props, new Authenticator() {
    override protected def getPasswordAuthentication(): PasswordAuthentication = {
      new PasswordAuthentication(username, password)
    }
  })
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_4(): Unit = {
  // MongoDB connection with hardcoded credentials
  // ruleid: scala-hardcoded-credentials-library-ide
  val mongoUri = "mongodb://admin:SuperSecretP@ss@localhost:27017/admin"
  val client = new MongoClient(new MongoClientURI(mongoUri))
  val database = client.getDatabase("mydb")
  val collection = database.getCollection("users")
  client.close()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_5(): Unit = {
  // API call with hardcoded API key
  val httpClient = HttpClients.createDefault()
  // ruleid: scala-hardcoded-credentials-library-ide
  val apiKey = "sk_test_PLACEHOLDER_KEY"
  val request = new HttpGet(s"https://api.stripe.com/v1/customers?api_key=$apiKey")
  val response = httpClient.execute(request)
  val responseBody = EntityUtils.toString(response.getEntity)
  httpClient.close()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_6(): Unit = {
  // SSH command with hardcoded password
  val host = "example.com"
  val user = "admin"
  // ruleid: scala-hardcoded-credentials-library-ide
  val password = "admin123"
  
  val sshCommand = s"sshpass -p '$password' ssh $user@$host 'ls -la'"
  sshCommand.!
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_7(): Unit = {
  // OAuth token hardcoded
  // ruleid: scala-hardcoded-credentials-library-ide
  val oauthToken = "ya29.a0AfH6SMBx-CIZfKLHY29gK3eQ5vfIeL9PnTMZ"
  val httpClient = HttpClients.createDefault()
  val request = new HttpGet("https://api.github.com/user/repos")
  request.addHeader("Authorization", s"Bearer $oauthToken")
  val response = httpClient.execute(request)
  val responseBody = EntityUtils.toString(response.getEntity)
  httpClient.close()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_8(): Unit = {
  // Hardcoded encryption key
  // ruleid: scala-hardcoded-credentials-library-ide
  val encryptionKey = "1234567890ABCDEF1234567890ABCDEF"
  val data = "Sensitive information"
  
  // Using the key for encryption (simplified example)
  val encryptedData = data.getBytes.map(b => (b ^ encryptionKey.charAt(0).toByte).toByte)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_9(): Unit = {
  // Firebase configuration with hardcoded API key
  case class FirebaseConfig(apiKey: String, authDomain: String, projectId: String)
  
  // ruleid: scala-hardcoded-credentials-library-ide
  val firebaseConfig = FirebaseConfig(
    apiKey = "AIzaSyBnTgUJCwPd_7vt7Xwh3tlkn_3MnTdV4Ys",
    authDomain = "my-app.firebaseapp.com",
    projectId = "my-app"
  )
  
  // Initialize Firebase (simplified)
  println(s"Initializing Firebase with API key: ${firebaseConfig.apiKey}")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_10(): Unit = {
  // FTP connection with hardcoded credentials
  import org.apache.commons.net.ftp.FTPClient
  
  val ftpClient = new FTPClient()
  val server = "ftp.example.com"
  val user = "ftpuser"
  // ruleid: scala-hardcoded-credentials-library-ide
  val password = "ftpP@ssw0rd"
  
  ftpClient.connect(server)
  ftpClient.login(user, password)
  ftpClient.disconnect()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_11(): Unit = {
  // Redis connection with hardcoded password
  import redis.clients.jedis.Jedis
  
  val jedis = new Jedis("localhost")
  // ruleid: scala-hardcoded-credentials-library-ide
  jedis.auth("RedisStrongP@ss123")
  val value = jedis.get("mykey")
  jedis.close()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_12(): Unit = {
  // Elasticsearch client with hardcoded credentials
  case class ElasticsearchConfig(url: String, username: String, password: String)
  
  // ruleid: scala-hardcoded-credentials-library-ide
  val esConfig = ElasticsearchConfig(
    url = "https://elasticsearch.example.com:9200",
    username = "elastic",
    password = "changeme123"
  )
  
  // Connect to Elasticsearch (simplified)
  println(s"Connecting to Elasticsearch with credentials: ${esConfig.username}:${esConfig.password}")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_13(): Unit = {
  // JWT signing with hardcoded secret
  import io.jsonwebtoken.Jwts
  import io.jsonwebtoken.SignatureAlgorithm
  import io.jsonwebtoken.security.Keys
  import java.nio.charset.StandardCharsets
  
  // ruleid: scala-hardcoded-credentials-library-ide
  val jwtSecret = "ThisIsAVerySecretKeyUsedForJWTSigning123456789"
  val key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8))
  
  val jwt = Jwts.builder()
    .setSubject("user123")
    .signWith(key, SignatureAlgorithm.HS256)
    .compact()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_14(): Unit = {
  // GraphQL API with hardcoded API token
  import org.apache.http.client.methods.HttpPost
  import org.apache.http.entity.StringEntity
  
  val httpClient = HttpClients.createDefault()
  val request = new HttpPost("https://api.github.com/graphql")
  
  // ruleid: scala-hardcoded-credentials-library-ide
  val apiToken = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789"
  request.addHeader("Authorization", s"Bearer $apiToken")
  
  val query = """{"query": "{ viewer { login } }"}"""
  request.setEntity(new StringEntity(query))
  
  val response = httpClient.execute(request)
  httpClient.close()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_15(): Unit = {
  // Twilio API with hardcoded credentials
  case class TwilioConfig(accountSid: String, authToken: String)
  
  // ruleid: scala-hardcoded-credentials-library-ide
  val twilioConfig = TwilioConfig(
    accountSid = "ACPLACEHOLDER_SECRET_32_CHARS",
    authToken = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
  )
  
  // Use Twilio API (simplified)
  val url = s"https://api.twilio.com/2010-04-01/Accounts/${twilioConfig.accountSid}/Messages.json"
  println(s"Sending request to Twilio with auth: ${twilioConfig.accountSid}:${twilioConfig.authToken}")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// True Negatives (Secure Code)

def good_case_1(): Unit = {
  // Database connection with credentials from environment variables
  val dbUrl = "jdbc:mysql://localhost:3306/mydb"
  val username = envOrElse("DB_USERNAME", "")
  // ok: scala-hardcoded-credentials-library-ide
  val password = envOrElse("DB_PASSWORD", "")
  
  val connection = DriverManager.getConnection(dbUrl, username, password)
  // Use connection for database operations
  connection.close()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_2(): Unit = {
  // AWS S3 access with credentials from environment variables
  // ok: scala-hardcoded-credentials-library-ide
  val awsAccessKey = envOrElse("AWS_ACCESS_KEY", "")
  val awsSecretKey = envOrElse("AWS_SECRET_KEY", "")
  
  val credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey)
  val s3Client = AmazonS3ClientBuilder.standard()
    .withCredentials(new AWSStaticCredentialsProvider(credentials))
    .withRegion("us-west-2")
    .build()
    
  val objects = s3Client.listObjects("my-bucket")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_3(): Unit = {
  // SMTP configuration with credentials from environment variables
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.gmail.com")
  props.put("mail.smtp.port", "587")
  props.put("mail.smtp.auth", "true")
  props.put("mail.smtp.starttls.enable", "true")
  
  // ok: scala-hardcoded-credentials-library-ide
  val username = envOrElse("SMTP_USERNAME", "")
  val password = envOrElse("SMTP_PASSWORD", "")
  
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
  // ok: scala-hardcoded-credentials-library-ide
  val mongoUser = envOrElse("MONGO_USER", "")
  val mongoPass = envOrElse("MONGO_PASS", "")
  val mongoHost = envOrElse("MONGO_HOST", "localhost:27017")
  
  val mongoUri = s"mongodb://$mongoUser:$mongoPass@$mongoHost/admin"
  val client = new MongoClient(new MongoClientURI(mongoUri))
  val database = client.getDatabase("mydb")
  val collection = database.getCollection("users")
  client.close()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_5(): Unit = {
  // API call with API key from environment variable
  val httpClient = HttpClients.createDefault()
  // ok: scala-hardcoded-credentials-library-ide
  val apiKey = envOrElse("STRIPE_API_KEY", "")
  val request = new HttpGet(s"https://api.stripe.com/v1/customers?api_key=$apiKey")
  val response = httpClient.execute(request)
  val responseBody = EntityUtils.toString(response.getEntity)
  httpClient.close()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_6(): Unit = {
  // SSH command with password from environment variable
  val host = "example.com"
  val user = envOrElse("SSH_USER", "")
  // ok: scala-hardcoded-credentials-library-ide
  val password = envOrElse("SSH_PASSWORD", "")
  
  val sshCommand = s"sshpass -p '$password' ssh $user@$host 'ls -la'"
  sshCommand.!
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_7(): Unit = {
  // OAuth token from environment variable
  // ok: scala-hardcoded-credentials-library-ide
  val oauthToken = envOrElse("GITHUB_OAUTH_TOKEN", "")
  val httpClient = HttpClients.createDefault()
  val request = new HttpGet("https://api.github.com/user/repos")
  request.addHeader("Authorization", s"Bearer $oauthToken")
  val response = httpClient.execute(request)
  val responseBody = EntityUtils.toString(response.getEntity)
  httpClient.close()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_8(): Unit = {
  // Encryption key from environment variable
  // ok: scala-hardcoded-credentials-library-ide
  val encryptionKey = envOrElse("ENCRYPTION_KEY", "")
  val data = "Sensitive information"
  
  // Using the key for encryption (simplified example)
  if (encryptionKey.nonEmpty) {
    val encryptedData = data.getBytes.map(b => (b ^ encryptionKey.charAt(0).toByte).toByte)
  }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_9(): Unit = {
  // Firebase configuration with API key from environment variable
  case class FirebaseConfig(apiKey: String, authDomain: String, projectId: String)
  
  // ok: scala-hardcoded-credentials-library-ide
  val firebaseConfig = FirebaseConfig(
    apiKey = envOrElse("FIREBASE_API_KEY", ""),
    authDomain = envOrElse("FIREBASE_AUTH_DOMAIN", ""),
    projectId = envOrElse("FIREBASE_PROJECT_ID", "")
  )
  
  // Initialize Firebase (simplified)
  println(s"Initializing Firebase with project: ${firebaseConfig.projectId}")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_10(): Unit = {
  // FTP connection with credentials from environment variables
  import org.apache.commons.net.ftp.FTPClient
  
  val ftpClient = new FTPClient()
  val server = envOrElse("FTP_SERVER", "")
  // ok: scala-hardcoded-credentials-library-ide
  val user = envOrElse("FTP_USER", "")
  val password = envOrElse("FTP_PASSWORD", "")
  
  ftpClient.connect(server)
  ftpClient.login(user, password)
  ftpClient.disconnect()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_11(): Unit = {
  // Redis connection with password from environment variable
  import redis.clients.jedis.Jedis
  
  val jedis = new Jedis("localhost")
  // ok: scala-hardcoded-credentials-library-ide
  val redisPassword = envOrElse("REDIS_PASSWORD", "")
  jedis.auth(redisPassword)
  val value = jedis.get("mykey")
  jedis.close()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_12(): Unit = {
  // Elasticsearch client with credentials from environment variables
  case class ElasticsearchConfig(url: String, username: String, password: String)
  
  // ok: scala-hardcoded-credentials-library-ide
  val esConfig = ElasticsearchConfig(
    url = envOrElse("ES_URL", "https://localhost:9200"),
    username = envOrElse("ES_USERNAME", ""),
    password = envOrElse("ES_PASSWORD", "")
  )
  
  // Connect to Elasticsearch (simplified)
  println(s"Connecting to Elasticsearch at ${esConfig.url}")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_13(): Unit = {
  // JWT signing with secret from environment variable
  import io.jsonwebtoken.Jwts
  import io.jsonwebtoken.SignatureAlgorithm
  import io.jsonwebtoken.security.Keys
  import java.nio.charset.StandardCharsets
  
  // ok: scala-hardcoded-credentials-library-ide
  val jwtSecret = envOrElse("JWT_SECRET", "")
  val key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8))
  
  val jwt = Jwts.builder()
    .setSubject("user123")
    .signWith(key, SignatureAlgorithm.HS256)
    .compact()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_14(): Unit = {
  // GraphQL API with API token from environment variable
  import org.apache.http.client.methods.HttpPost
  import org.apache.http.entity.StringEntity
  
  val httpClient = HttpClients.createDefault()
  val request = new HttpPost("https://api.github.com/graphql")
  
  // ok: scala-hardcoded-credentials-library-ide
  val apiToken = envOrElse("GITHUB_API_TOKEN", "")
  request.addHeader("Authorization", s"Bearer $apiToken")
  
  val query = """{"query": "{ viewer { login } }"}"""
  request.setEntity(new StringEntity(query))
  
  val response = httpClient.execute(request)
  httpClient.close()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_15(): Unit = {
  // Twilio API with credentials from environment variables
  case class TwilioConfig(accountSid: String, authToken: String)
  
  // ok: scala-hardcoded-credentials-library-ide
  val twilioConfig = TwilioConfig(
    accountSid = envOrElse("TWILIO_ACCOUNT_SID", ""),
    authToken = envOrElse("TWILIO_AUTH_TOKEN", "")
  )
  
  // Use Twilio API (simplified)
  val url = s"https://api.twilio.com/2010-04-01/Accounts/${twilioConfig.accountSid}/Messages.json"
  println(s"Sending request to Twilio for account: ${twilioConfig.accountSid}")
}
// {/fact}