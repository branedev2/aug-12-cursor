import java.io._
import java.net._
import javax.net.ssl._
import scala.io.Source
import scala.util.{Try, Success, Failure}
import scala.concurrent.{Future, ExecutionContext}
import scala.concurrent.ExecutionContext.Implicits.global

object UnencryptedSocketExamples {

  // True Positive Examples (Vulnerable Code)

  def bad_case_1(): Unit = {
    val socket = new Socket("api.example.com", 80)
    val out = new PrintWriter(socket.getOutputStream(), true)
    // ruleid: scala-unencrypted-socket
    out.println("username=admin&password=secret123")
    out.close()
    socket.close()
  }

  def bad_case_2(): Unit = {
    val serverAddress = InetAddress.getByName("payments.example.com")
    val socket = new Socket(serverAddress, 8080)
    val out = new PrintWriter(socket.getOutputStream(), true)
    val in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
    
    // ruleid: scala-unencrypted-socket
    out.println("creditcard=4111111111111111&cvv=123")
    val response = in.readLine()
    
    out.close()
    in.close()
    socket.close()
  }

  def bad_case_3(): Unit = {
    val url = new URL("http://api.example.com/login")
    val connection = url.openConnection().asInstanceOf[HttpURLConnection]
    connection.setRequestMethod("POST")
    connection.setDoOutput(true)
    
    val out = new OutputStreamWriter(connection.getOutputStream)
    // ruleid: scala-unencrypted-socket
    out.write("username=admin&password=secret123")
    out.flush()
    out.close()
    
    val responseCode = connection.getResponseCode
    connection.disconnect()
  }

  def bad_case_4(): Unit = {
    val socket = new Socket()
    val endpoint = new InetSocketAddress("auth.example.com", 80)
    socket.connect(endpoint)
    
    val out = new DataOutputStream(socket.getOutputStream)
    // ruleid: scala-unencrypted-socket
    out.writeBytes("token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
    out.flush()
    out.close()
    socket.close()
  }

  def bad_case_5(): Unit = {
    val url = new URL("http://api.example.com/user/profile")
    val connection = url.openConnection().asInstanceOf[HttpURLConnection]
    connection.setRequestMethod("GET")
    connection.setRequestProperty("Authorization", "Bearer secret-token-12345")
    
    // ruleid: scala-unencrypted-socket
    val responseCode = connection.getResponseCode
    val inputStream = connection.getInputStream
    val content = Source.fromInputStream(inputStream).mkString
    inputStream.close()
    connection.disconnect()
  }

  def bad_case_6(): Unit = {
    val serverName = "database.example.com"
    val port = 3306
    
    val socket = new Socket(serverName, port)
    val out = new PrintWriter(socket.getOutputStream(), true)
    
    // ruleid: scala-unencrypted-socket
    out.println("SELECT * FROM users WHERE username='admin' AND password='password123'")
    out.close()
    socket.close()
  }

  def bad_case_7(): Unit = {
    val url = new URL("http://api.example.com/v1/payment")
    val connection = url.openConnection().asInstanceOf[HttpURLConnection]
    connection.setRequestMethod("POST")
    connection.setDoOutput(true)
    connection.setRequestProperty("Content-Type", "application/json")
    
    val jsonPayload = """{"cardNumber":"4111111111111111","expiryDate":"12/25","cvv":"123"}"""
    val out = new OutputStreamWriter(connection.getOutputStream)
    // ruleid: scala-unencrypted-socket
    out.write(jsonPayload)
    out.flush()
    out.close()
    
    val responseCode = connection.getResponseCode
    connection.disconnect()
  }

  def bad_case_8(): Unit = {
    val socket = new Socket()
    socket.connect(new InetSocketAddress("mail.example.com", 25))
    
    val reader = new BufferedReader(new InputStreamReader(socket.getInputStream()))
    val writer = new PrintWriter(socket.getOutputStream(), true)
    
    // SMTP communication over unencrypted socket
    writer.println("HELO example.com")
    reader.readLine()
    writer.println("MAIL FROM: <sender@example.com>")
    reader.readLine()
    writer.println("RCPT TO: <recipient@example.com>")
    reader.readLine()
    writer.println("DATA")
    reader.readLine()
    // ruleid: scala-unencrypted-socket
    writer.println("Subject: Confidential Information\r\n\r\nThis contains sensitive data: SSN 123-45-6789")
    writer.println(".")
    reader.readLine()
    
    writer.close()
    reader.close()
    socket.close()
  }

  def bad_case_9(): Unit = {
    val serverSocket = new ServerSocket(8080)
    val clientSocket = serverSocket.accept()
    
    val out = new PrintWriter(clientSocket.getOutputStream(), true)
    val in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))
    
    val inputLine = in.readLine()
    // ruleid: scala-unencrypted-socket
    out.println("Your personal data: " + inputLine)
    
    out.close()
    in.close()
    clientSocket.close()
    serverSocket.close()
  }

  def bad_case_10(): Unit = {
    val url = new URL("http://api.example.com/v1/transfer")
    val connection = url.openConnection().asInstanceOf[HttpURLConnection]
    connection.setRequestMethod("POST")
    connection.setDoOutput(true)
    
    val data = "amount=1000&fromAccount=12345&toAccount=67890"
    val out = new OutputStreamWriter(connection.getOutputStream)
    // ruleid: scala-unencrypted-socket
    out.write(data)
    out.flush()
    out.close()
    
    val in = new BufferedReader(new InputStreamReader(connection.getInputStream))
    val response = in.readLine()
    in.close()
    connection.disconnect()
  }

  def bad_case_11(): Unit = {
    val socket = new Socket("api.example.com", 80)
    val out = new DataOutputStream(socket.getOutputStream)
    
    val sensitiveData = "api_key=abcdef123456&user_id=12345"
    // ruleid: scala-unencrypted-socket
    out.writeBytes(sensitiveData)
    out.flush()
    out.close()
    socket.close()
  }

  def bad_case_12(): Unit = {
    val url = new URL("http://login.example.com/auth")
    val connection = url.openConnection().asInstanceOf[HttpURLConnection]
    connection.setRequestMethod("POST")
    connection.setDoOutput(true)
    
    val credentials = "username=admin&password=P@ssw0rd!"
    val out = new OutputStreamWriter(connection.getOutputStream)
    // ruleid: scala-unencrypted-socket
    out.write(credentials)
    out.flush()
    out.close()
    
    val responseCode = connection.getResponseCode
    connection.disconnect()
  }

  def bad_case_13(): Unit = {
    def sendDataOverSocket(data: String): Unit = {
      val socket = new Socket("api.example.com", 80)
      val out = new PrintWriter(socket.getOutputStream(), true)
      // ruleid: scala-unencrypted-socket
      out.println(data)
      out.close()
      socket.close()
    }
    
    val sensitiveData = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    sendDataOverSocket(sensitiveData)
  }

  def bad_case_14(): Unit = {
    val socket = new Socket()
    socket.connect(new InetSocketAddress("chat.example.com", 9000))
    
    val out = new PrintWriter(socket.getOutputStream(), true)
    val in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
    
    // Chat application sending messages over unencrypted socket
    // ruleid: scala-unencrypted-socket
    out.println("USER admin")
    out.println("PASS secret123")
    
    val response = in.readLine()
    out.close()
    in.close()
    socket.close()
  }

  def bad_case_15(): Unit = {
    val url = new URL("http://api.example.com/v1/user/12345")
    val connection = url.openConnection().asInstanceOf[HttpURLConnection]
    connection.setRequestMethod("GET")
    connection.setRequestProperty("Authorization", "Basic YWRtaW46cGFzc3dvcmQxMjM=") // admin:password123 in Base64
    
    // ruleid: scala-unencrypted-socket
    val responseCode = connection.getResponseCode
    val inputStream = connection.getInputStream
    val content = Source.fromInputStream(inputStream).mkString
    inputStream.close()
    connection.disconnect()
  }

  // True Negative Examples (Secure Code)

  def good_case_1(): Unit = {
    val url = new URL("https://api.example.com/login")
    val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
    connection.setRequestMethod("POST")
    connection.setDoOutput(true)
    
    val out = new OutputStreamWriter(connection.getOutputStream)
    // ok: scala-unencrypted-socket
    out.write("username=admin&password=secret123")
    out.flush()
    out.close()
    
    val responseCode = connection.getResponseCode
    connection.disconnect()
  }

  def good_case_2(): Unit = {
    val url = new URL("https://payments.example.com/process")
    val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
    connection.setRequestMethod("POST")
    connection.setDoOutput(true)
    
    val out = new OutputStreamWriter(connection.getOutputStream)
    // ok: scala-unencrypted-socket
    out.write("creditcard=4111111111111111&cvv=123")
    out.flush()
    out.close()
    
    val responseCode = connection.getResponseCode
    connection.disconnect()
  }

  def good_case_3(): Unit = {
    // Create SSL Socket Factory
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    val sslSocketFactory = sslContext.getSocketFactory()
    
    // Create secure socket
    val socket = sslSocketFactory.createSocket("api.example.com", 443)
    val out = new PrintWriter(socket.getOutputStream(), true)
    
    // ok: scala-unencrypted-socket
    out.println("username=admin&password=secret123")
    out.close()
    socket.close()
  }

  def good_case_4(): Unit = {
    val url = new URL("https://api.example.com/user/profile")
    val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
    connection.setRequestMethod("GET")
    connection.setRequestProperty("Authorization", "Bearer secret-token-12345")
    
    // ok: scala-unencrypted-socket
    val responseCode = connection.getResponseCode
    val inputStream = connection.getInputStream
    val content = Source.fromInputStream(inputStream).mkString
    inputStream.close()
    connection.disconnect()
  }

  def good_case_5(): Unit = {
    // Setting up SSL Socket Factory with custom trust manager
    val sslContext = SSLContext.getInstance("TLS")
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    trustManagerFactory.init(null.asInstanceOf[KeyStore])
    sslContext.init(null, trustManagerFactory.getTrustManagers, null)
    
    val sslSocketFactory = sslContext.getSocketFactory()
    val socket = sslSocketFactory.createSocket("database.example.com", 3306)
    val out = new PrintWriter(socket.getOutputStream(), true)
    
    // ok: scala-unencrypted-socket
    out.println("SELECT * FROM users WHERE username='admin' AND password='password123'")
    out.close()
    socket.close()
  }

  def good_case_6(): Unit = {
    val url = new URL("https://api.example.com/v1/payment")
    val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
    connection.setRequestMethod("POST")
    connection.setDoOutput(true)
    connection.setRequestProperty("Content-Type", "application/json")
    
    val jsonPayload = """{"cardNumber":"4111111111111111","expiryDate":"12/25","cvv":"123"}"""
    val out = new OutputStreamWriter(connection.getOutputStream)
    // ok: scala-unencrypted-socket
    out.write(jsonPayload)
    out.flush()
    out.close()
    
    val responseCode = connection.getResponseCode
    connection.disconnect()
  }

  def good_case_7(): Unit = {
    // Setting up SSL Socket Factory for secure SMTP (SMTPS)
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    val sslSocketFactory = sslContext.getSocketFactory()
    
    // Create secure socket for SMTPS (port 465)
    val socket = sslSocketFactory.createSocket("mail.example.com", 465)
    val reader = new BufferedReader(new InputStreamReader(socket.getInputStream()))
    val writer = new PrintWriter(socket.getOutputStream(), true)
    
    // SMTPS communication over encrypted socket
    writer.println("HELO example.com")
    reader.readLine()
    writer.println("MAIL FROM: <sender@example.com>")
    reader.readLine()
    writer.println("RCPT TO: <recipient@example.com>")
    reader.readLine()
    writer.println("DATA")
    reader.readLine()
    // ok: scala-unencrypted-socket
    writer.println("Subject: Confidential Information\r\n\r\nThis contains sensitive data: SSN 123-45-6789")
    writer.println(".")
    reader.readLine()
    
    writer.close()
    reader.close()
    socket.close()
  }

  def good_case_8(): Unit = {
    // Setting up SSL Server Socket
    val sslContext = SSLContext.getInstance("TLS")
    val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm)
    
    val keyStore = KeyStore.getInstance("JKS")
    val keyStorePassword = "password".toCharArray
    keyStore.load(new FileInputStream("keystore.jks"), keyStorePassword)
    
    keyManagerFactory.init(keyStore, keyStorePassword)
    sslContext.init(keyManagerFactory.getKeyManagers, null, null)
    
    val serverSocketFactory = sslContext.getServerSocketFactory()
    val serverSocket = serverSocketFactory.createServerSocket(8443)
    
    val clientSocket = serverSocket.accept()
    val out = new PrintWriter(clientSocket.getOutputStream(), true)
    val in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))
    
    val inputLine = in.readLine()
    // ok: scala-unencrypted-socket
    out.println("Your personal data: " + inputLine)
    
    out.close()
    in.close()
    clientSocket.close()
    serverSocket.close()
  }

  def good_case_9(): Unit = {
    val url = new URL("https://api.example.com/v1/transfer")
    val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
    connection.setRequestMethod("POST")
    connection.setDoOutput(true)
    
    val data = "amount=1000&fromAccount=12345&toAccount=67890"
    val out = new OutputStreamWriter(connection.getOutputStream)
    // ok: scala-unencrypted-socket
    out.write(data)
    out.flush()
    out.close()
    
    val in = new BufferedReader(new InputStreamReader(connection.getInputStream))
    val response = in.readLine()
    in.close()
    connection.disconnect()
  }

  def good_case_10(): Unit = {
    // Create SSL Socket Factory
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    val sslSocketFactory = sslContext.getSocketFactory()
    
    val socket = sslSocketFactory.createSocket("api.example.com", 443)
    val out = new DataOutputStream(socket.getOutputStream)
    
    val sensitiveData = "api_key=abcdef123456&user_id=12345"
    // ok: scala-unencrypted-socket
    out.writeBytes(sensitiveData)
    out.flush()
    out.close()
    socket.close()
  }

  def good_case_11(): Unit = {
    val url = new URL("https://login.example.com/auth")
    val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
    connection.setRequestMethod("POST")
    connection.setDoOutput(true)
    
    val credentials = "username=admin&password=P@ssw0rd!"
    val out = new OutputStreamWriter(connection.getOutputStream)
    // ok: scala-unencrypted-socket
    out.write(credentials)
    out.flush()
    out.close()
    
    val responseCode = connection.getResponseCode
    connection.disconnect()
  }

  def good_case_12(): Unit = {
    def sendDataOverSecureSocket(data: String): Unit = {
      val sslContext = SSLContext.getInstance("TLS")
      sslContext.init(null, null, null)
      val sslSocketFactory = sslContext.getSocketFactory()
      
      val socket = sslSocketFactory.createSocket("api.example.com", 443)
      val out = new PrintWriter(socket.getOutputStream(), true)
      // ok: scala-unencrypted-socket
      out.println(data)
      out.close()
      socket.close()
    }
    
    val sensitiveData = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    sendDataOverSecureSocket(sensitiveData)
  }

  def good_case_13(): Unit = {
    // Setting up SSL Socket Factory
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    val sslSocketFactory = sslContext.getSocketFactory()
    
    val socket = sslSocketFactory.createSocket("chat.example.com", 9443)
    val out = new PrintWriter(socket.getOutputStream(), true)
    val in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
    
    // Chat application sending messages over encrypted socket
    // ok: scala-unencrypted-socket
    out.println("USER admin")
    out.println("PASS secret123")
    
    val response = in.readLine()
    out.close()
    in.close()
    socket.close()
  }

  def good_case_14(): Unit = {
    val url = new URL("https://api.example.com/v1/user/12345")
    val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
    connection.setRequestMethod("GET")
    connection.setRequestProperty("Authorization", "Basic YWRtaW46cGFzc3dvcmQxMjM=") // admin:password123 in Base64
    
    // ok: scala-unencrypted-socket
    val responseCode = connection.getResponseCode
    val inputStream = connection.getInputStream
    val content = Source.fromInputStream(inputStream).mkString
    inputStream.close()
    connection.disconnect()
  }

  def good_case_15(): Unit = {
    // Using non-sensitive data over unencrypted connection is acceptable
    val socket = new Socket("api.example.com", 80)
    val out = new PrintWriter(socket.getOutputStream(), true)
    
    // ok: scala-unencrypted-socket
    out.println("page=1&limit=10&sort=name") // Public, non-sensitive data
    out.close()
    socket.close()
  }
}