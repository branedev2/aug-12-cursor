import java.sql.{Connection, DriverManager}
import scala.io.Source
import com.amazonaws.auth.{AWSStaticCredentialsProvider, BasicAWSCredentials}
import com.amazonaws.services.s3.AmazonS3ClientBuilder
import javax.crypto.spec.SecretKeySpec
import java.util.Properties
import com.mongodb.{MongoClient, MongoClientURI}
import com.typesafe.config.ConfigFactory
import scala.sys.process._
import javax.mail.{Authenticator, PasswordAuthentication, Session}
import javax.mail.internet.{InternetAddress, MimeMessage}
import java.io.File
import com.jcraft.jsch.{JSch, Session => JSchSession}
import org.apache.http.impl.client.HttpClients
import org.apache.http.auth.{AuthScope, UsernamePasswordCredentials}
import org.apache.http.impl.client.BasicCredentialsProvider
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(): Unit = {
  // Database connection with hardcoded credentials
  val url = "jdbc:mysql://localhost:3306/mydb"
  val username = "admin"
  // ruleid: scala-hardcoded-credentials
  val password = "password123"
  val connection = DriverManager.getConnection(url, username, password)
  
  // Use connection
  val statement = connection.createStatement()
  val resultSet = statement.executeQuery("SELECT * FROM users")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_2(): Unit = {
  // MongoDB connection with hardcoded credentials
  // ruleid: scala-hardcoded-credentials
  val uri = "mongodb://admin:secret@localhost:27017/admin"
  val client = new MongoClient(new MongoClientURI(uri))
  
  val database = client.getDatabase("users")
  val collection = database.getCollection("profiles")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_3(): Unit = {
  // AWS S3 access with hardcoded credentials
  // ruleid: scala-hardcoded-credentials
  val accessKey = "AKIA_PLACEHOLDER_ACCESS_KEY"
  val secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  
  val credentials = new BasicAWSCredentials(accessKey, secretKey)
  val s3Client = AmazonS3ClientBuilder.standard()
    .withCredentials(new AWSStaticCredentialsProvider(credentials))
    .withRegion("us-west-2")
    .build()
    
  val objects = s3Client.listObjects("my-bucket")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_4(): Unit = {
  // SMTP configuration with hardcoded credentials
  val props = new Properties()
  props.put("mail.smtp.auth", "true")
  props.put("mail.smtp.starttls.enable", "true")
  props.put("mail.smtp.host", "smtp.gmail.com")
  props.put("mail.smtp.port", "587")
  
  // ruleid: scala-hardcoded-credentials
  val username = "myemail@gmail.com"
  val password = "myGmailPassword123"
  
  val session = Session.getInstance(props, new Authenticator() {
    override protected def getPasswordAuthentication(): PasswordAuthentication = {
      new PasswordAuthentication(username, password)
    }
  })
  
  val message = new MimeMessage(session)
  message.setFrom(new InternetAddress("from@example.com"))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_5(): Unit = {
  // SSH connection with hardcoded credentials
  val jsch = new JSch()
  val host = "example.com"
  val user = "sshuser"
  // ruleid: scala-hardcoded-credentials
  val password = "ssh-password-123"
  
  val session = jsch.getSession(user, host, 22)
  session.setPassword(password)
  session.setConfig("StrictHostKeyChecking", "no")
  session.connect()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_6(): Unit = {
  // API authentication with hardcoded token
  // ruleid: scala-hardcoded-credentials
  val apiKey = "PLACEHOLDER_SECRET_32_CHARS"
  
  val url = s"https://api.example.com/data?api_key=$apiKey"
  val response = scala.io.Source.fromURL(url).mkString
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_7(): Unit = {
  // Database connection with empty password
  val url = "jdbc:postgresql://localhost:5432/mydb"
  val username = "postgres"
  // ruleid: scala-hardcoded-credentials
  val password = ""
  
  val connection = DriverManager.getConnection(url, username, password)
  val statement = connection.createStatement()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_8(): Unit = {
  // Encryption with hardcoded key
  val plainText = "Sensitive data"
  // ruleid: scala-hardcoded-credentials
  val keyString = "ThisIsA32ByteKeyForAES256Encryption"
  val key = new SecretKeySpec(keyString.getBytes("UTF-8"), "AES")
  
  val cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding")
  cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key)
  val encrypted = cipher.doFinal(plainText.getBytes("UTF-8"))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_9(): Unit = {
  // HTTP Basic Auth with hardcoded credentials
  val credentialsProvider = new BasicCredentialsProvider()
  // ruleid: scala-hardcoded-credentials
  credentialsProvider.setCredentials(
    AuthScope.ANY,
    new UsernamePasswordCredentials("admin", "admin123")
  )
  
  val httpClient = HttpClients.custom()
    .setDefaultCredentialsProvider(credentialsProvider)
    .build()
  
  val response = httpClient.execute(new org.apache.http.client.methods.HttpGet("https://api.example.com"))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_10(): Unit = {
  // FTP connection with hardcoded credentials
  import org.apache.commons.net.ftp.FTPClient
  
  val ftpClient = new FTPClient()
  val server = "ftp.example.com"
  val user = "ftpuser"
  // ruleid: scala-hardcoded-credentials
  val pass = "ftpP@ssw0rd"
  
  ftpClient.connect(server, 21)
  ftpClient.login(user, pass)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_11(): Unit = {
  // Redis connection with hardcoded password
  import redis.clients.jedis.Jedis
  
  val jedis = new Jedis("localhost")
  // ruleid: scala-hardcoded-credentials
  jedis.auth("redis-secret-password")
  
  jedis.set("key", "value")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_12(): Unit = {
  // Command execution with hardcoded sudo password
  import scala.sys.process._
  
  val command = "sudo apt-get update"
  // ruleid: scala-hardcoded-credentials
  val process = Process(Seq("bash", "-c", s"echo 'sudoPassword' | sudo -S $command"))
  
  process.!
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_13(): Unit = {
  // OAuth client with hardcoded credentials
  // ruleid: scala-hardcoded-credentials
  val clientId = "oauth-client-id"
  val clientSecret = "oauth-client-secret"
  
  val tokenUrl = "https://oauth.example.com/token"
  val authString = s"$clientId:$clientSecret"
  val encodedAuth = java.util.Base64.getEncoder.encodeToString(authString.getBytes)
  
  // Use in HTTP request
  val connection = new java.net.URL(tokenUrl).openConnection().asInstanceOf[java.net.HttpURLConnection]
  connection.setRequestProperty("Authorization", s"Basic $encodedAuth")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_14(): Unit = {
  // Azure connection with hardcoded credentials
  import com.microsoft.azure.storage.CloudStorageAccount
  import com.microsoft.azure.storage.blob.CloudBlobClient
  
  // ruleid: scala-hardcoded-credentials
  val storageConnectionString = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey123456789;"
  
  val storageAccount = CloudStorageAccount.parse(storageConnectionString)
  val blobClient = storageAccount.createCloudBlobClient()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_15(): Unit = {
  // LDAP connection with hardcoded credentials
  import javax.naming.Context
  import javax.naming.directory.InitialDirContext
  
  val env = new java.util.Hashtable[String, String]()
  env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
  env.put(Context.PROVIDER_URL, "ldap://ldap.example.com:389")
  env.put(Context.SECURITY_AUTHENTICATION, "simple")
  env.put(Context.SECURITY_PRINCIPAL, "cn=admin,dc=example,dc=com")
  // ruleid: scala-hardcoded-credentials
  env.put(Context.SECURITY_CREDENTIALS, "ldapAdminPassword")
  
  val ctx = new InitialDirContext(env)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// True Negatives (Secure Code)

def good_case_1(): Unit = {
  // Database connection with credentials from environment variables
  val url = "jdbc:mysql://localhost:3306/mydb"
  val username = sys.env.getOrElse("DB_USERNAME", "")
  // ok: scala-hardcoded-credentials
  val password = sys.env.getOrElse("DB_PASSWORD", "")
  
  val connection = DriverManager.getConnection(url, username, password)
  val statement = connection.createStatement()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_2(): Unit = {
  // MongoDB connection with credentials from environment variables
  val username = sys.env.getOrElse("MONGO_USERNAME", "")
  // ok: scala-hardcoded-credentials
  val password = sys.env.getOrElse("MONGO_PASSWORD", "")
  val host = sys.env.getOrElse("MONGO_HOST", "localhost")
  
  val uri = s"mongodb://$username:$password@$host:27017/admin"
  val client = new MongoClient(new MongoClientURI(uri))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_3(): Unit = {
  // AWS S3 access with credentials from environment variables
  // ok: scala-hardcoded-credentials
  val accessKey = sys.env.getOrElse("AWS_ACCESS_KEY", "")
  val secretKey = sys.env.getOrElse("AWS_SECRET_KEY", "")
  
  val credentials = new BasicAWSCredentials(accessKey, secretKey)
  val s3Client = AmazonS3ClientBuilder.standard()
    .withCredentials(new AWSCredentialsProvider {
      override def getCredentials = credentials
      override def refresh(): Unit = {}
    })
    .withRegion("us-west-2")
    .build()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_4(): Unit = {
  // SMTP configuration with credentials from configuration file
  val config = ConfigFactory.load()
  
  val props = new Properties()
  props.put("mail.smtp.auth", "true")
  props.put("mail.smtp.starttls.enable", "true")
  props.put("mail.smtp.host", config.getString("smtp.host"))
  props.put("mail.smtp.port", config.getString("smtp.port"))
  
  // ok: scala-hardcoded-credentials
  val username = config.getString("smtp.username")
  val password = config.getString("smtp.password")
  
  val session = Session.getInstance(props, new Authenticator() {
    override protected def getPasswordAuthentication(): PasswordAuthentication = {
      new PasswordAuthentication(username, password)
    }
  })
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_5(): Unit = {
  // SSH connection with credentials from secure source
  val jsch = new JSch()
  val host = "example.com"
  val user = sys.env.getOrElse("SSH_USER", "")
  
  // ok: scala-hardcoded-credentials
  val keyFile = sys.env.getOrElse("SSH_KEY_FILE", "")
  jsch.addIdentity(keyFile)
  
  val session = jsch.getSession(user, host, 22)
  session.setConfig("StrictHostKeyChecking", "no")
  session.connect()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_6(): Unit = {
  // API authentication with token from environment variable
  // ok: scala-hardcoded-credentials
  val apiKey = sys.env.getOrElse("API_KEY", "")
  
  val url = s"https://api.example.com/data?api_key=$apiKey"
  val response = scala.io.Source.fromURL(url).mkString
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_7(): Unit = {
  // Database connection with credentials from properties file
  val props = new Properties()
  props.load(new java.io.FileInputStream("config.properties"))
  
  val url = props.getProperty("db.url")
  val username = props.getProperty("db.username")
  // ok: scala-hardcoded-credentials
  val password = props.getProperty("db.password")
  
  val connection = DriverManager.getConnection(url, username, password)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_8(): Unit = {
  // Encryption with key from secure storage
  import java.security.KeyStore
  
  val plainText = "Sensitive data"
  val keyStore = KeyStore.getInstance("JCEKS")
  
  // ok: scala-hardcoded-credentials
  val keyStorePassword = sys.env.getOrElse("KEYSTORE_PASSWORD", "")
  keyStore.load(new java.io.FileInputStream("keystore.jceks"), keyStorePassword.toCharArray)
  
  val key = keyStore.getKey("aesKey", keyStorePassword.toCharArray)
  val cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding")
  cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_9(): Unit = {
  // HTTP Basic Auth with credentials from secure source
  val credentialsProvider = new BasicCredentialsProvider()
  
  // ok: scala-hardcoded-credentials
  val username = sys.env.getOrElse("API_USERNAME", "")
  val password = sys.env.getOrElse("API_PASSWORD", "")
  
  credentialsProvider.setCredentials(
    AuthScope.ANY,
    new UsernamePasswordCredentials(username, password)
  )
  
  val httpClient = HttpClients.custom()
    .setDefaultCredentialsProvider(credentialsProvider)
    .build()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_10(): Unit = {
  // FTP connection with credentials from configuration
  import org.apache.commons.net.ftp.FTPClient
  
  val config = ConfigFactory.load()
  val ftpClient = new FTPClient()
  
  val server = config.getString("ftp.server")
  val user = config.getString("ftp.username")
  // ok: scala-hardcoded-credentials
  val pass = config.getString("ftp.password")
  
  ftpClient.connect(server, 21)
  ftpClient.login(user, pass)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_11(): Unit = {
  // Redis connection with password from environment variable
  import redis.clients.jedis.Jedis
  
  val jedis = new Jedis("localhost")
  // ok: scala-hardcoded-credentials
  val redisPassword = sys.env.getOrElse("REDIS_PASSWORD", "")
  jedis.auth(redisPassword)
  
  jedis.set("key", "value")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_12(): Unit = {
  // Command execution with sudo password from secure input
  import scala.io.StdIn
  
  val command = "sudo apt-get update"
  
  // ok: scala-hardcoded-credentials
  println("Enter sudo password:")
  val password = StdIn.readLine()
  
  val process = Process(Seq("bash", "-c", s"echo '$password' | sudo -S $command"))
  process.!
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_13(): Unit = {
  // OAuth client with credentials from environment variables
  // ok: scala-hardcoded-credentials
  val clientId = sys.env.getOrElse("OAUTH_CLIENT_ID", "")
  val clientSecret = sys.env.getOrElse("OAUTH_CLIENT_SECRET", "")
  
  val tokenUrl = "https://oauth.example.com/token"
  val authString = s"$clientId:$clientSecret"
  val encodedAuth = java.util.Base64.getEncoder.encodeToString(authString.getBytes)
  
  // Use in HTTP request
  val connection = new java.net.URL(tokenUrl).openConnection().asInstanceOf[java.net.HttpURLConnection]
  connection.setRequestProperty("Authorization", s"Basic $encodedAuth")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_14(): Unit = {
  // Azure connection with credentials from environment variables
  import com.microsoft.azure.storage.CloudStorageAccount
  
  // ok: scala-hardcoded-credentials
  val accountName = sys.env.getOrElse("AZURE_ACCOUNT_NAME", "")
  val accountKey = sys.env.getOrElse("AZURE_ACCOUNT_KEY", "")
  
  val storageConnectionString = s"DefaultEndpointsProtocol=https;AccountName=$accountName;AccountKey=$accountKey;"
  val storageAccount = CloudStorageAccount.parse(storageConnectionString)
  val blobClient = storageAccount.createCloudBlobClient()
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_15(): Unit = {
  // LDAP connection with credentials from secure source
  import javax.naming.Context
  import javax.naming.directory.InitialDirContext
  
  val config = ConfigFactory.load()
  
  val env = new java.util.Hashtable[String, String]()
  env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
  env.put(Context.PROVIDER_URL, config.getString("ldap.url"))
  env.put(Context.SECURITY_AUTHENTICATION, "simple")
  env.put(Context.SECURITY_PRINCIPAL, config.getString("ldap.principal"))
  // ok: scala-hardcoded-credentials
  env.put(Context.SECURITY_CREDENTIALS, config.getString("ldap.credentials"))
  
  val ctx = new InitialDirContext(env)
}
// {/fact}