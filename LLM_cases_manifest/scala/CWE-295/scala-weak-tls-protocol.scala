import javax.net.ssl._
import java.security.SecureRandom
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import akka.http.scaladsl.{ConnectionContext, Http, HttpsConnectionContext}
import akka.http.scaladsl.model._
import akka.http.scaladsl.server.Directives._
import akka.actor.ActorSystem
import com.typesafe.config.ConfigFactory
import play.api.mvc._
import play.api.libs.ws._
import play.api.libs.ws.ahc.AhcWSClient
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.impl.client.HttpClients
import org.apache.http.ssl.SSLContexts
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.CloseableHttpClient
// {fact rule=improper-certificate-validation@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(): Unit = {
  // Creating an SSLContext with an insecure protocol
  val sslContext = SSLContext.getInstance("SSLv3")
  // ruleid: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val sslSocketFactory = sslContext.getSocketFactory()
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_2(): Unit = {
  val sc = SSLContext.getInstance("TLSv1")
  // ruleid: scala-weak-tls-protocol
  sc.init(null, null, new SecureRandom())
  val sslSocketFactory = sc.getSocketFactory()
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_3(): Unit = {
  // Creating an HttpsURLConnection with weak protocol
  val url = new java.net.URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[javax.net.ssl.HttpsURLConnection]
  val sslContext = SSLContext.getInstance("TLSv1.0")
  // ruleid: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  connection.setSSLSocketFactory(sslContext.getSocketFactory())
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_4(): Unit = {
  // Using weak protocol with Apache HttpClient
  val sslContext = SSLContext.getInstance("SSLv3")
  // ruleid: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val sslsf = new SSLConnectionSocketFactory(
    sslContext,
    Array("SSLv3"),
    null,
    SSLConnectionSocketFactory.getDefaultHostnameVerifier
  )
  val httpClient = HttpClients.custom().setSSLSocketFactory(sslsf).build()
}
// {/fact}

def bad_case_5()(implicit system: ActorSystem): Future[HttpResponse] = {
  // Using weak protocol with Akka HTTP
  val sslContext = SSLContext.getInstance("TLSv1")
  // ruleid: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val https = ConnectionContext.httpsClient(sslContext)
  Http().singleRequest(
    HttpRequest(uri = "https://example.com"),
    https
  )
}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_6(): Unit = {
  // Creating custom SSLContext with multiple protocols including weak ones
  val sslContext = SSLContext.getInstance("TLS")
  // ruleid: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val sslParameters = sslContext.getDefaultSSLParameters
  sslParameters.setProtocols(Array("TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"))
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_7(): Unit = {
  // Creating an SSLEngine with weak protocols
  val sslContext = SSLContext.getInstance("TLS")
  // ruleid: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val engine = sslContext.createSSLEngine()
  engine.setEnabledProtocols(Array("TLSv1", "SSLv3"))
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_8(): CloseableHttpClient = {
  // Creating Apache HttpClient with weak protocols
  val sslContext = SSLContexts.custom().build()
  // ruleid: scala-weak-tls-protocol
  val socketFactory = new SSLConnectionSocketFactory(
    sslContext,
    Array("TLSv1.0", "TLSv1.1"),
    null,
    SSLConnectionSocketFactory.getDefaultHostnameVerifier
  )
  HttpClients.custom().setSSLSocketFactory(socketFactory).build()
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_9(): Unit = {
  // Configuring weak protocols in a custom TrustManager
  val sslContext = SSLContext.getInstance("TLSv1")
  // ruleid: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
  trustManagerFactory.init(null.asInstanceOf[java.security.KeyStore])
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_10(): Unit = {
  // Using weak protocol with custom KeyManager
  val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm)
  val sslContext = SSLContext.getInstance("SSLv3")
  // ruleid: scala-weak-tls-protocol
  sslContext.init(keyManagerFactory.getKeyManagers, null, new SecureRandom())
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_11(): Unit = {
  // Using weak protocol with Play WS client
  val sslConfig = new play.api.libs.ws.ssl.Config.Builder()
    .withEnabledProtocols(Array("TLSv1", "SSLv3"))
    .build()
  
  // ruleid: scala-weak-tls-protocol
  val sslContext = SSLContext.getInstance("TLSv1")
  sslContext.init(null, null, new SecureRandom())
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_12(): Unit = {
  // Creating a server socket with weak protocol
  val sslContext = SSLContext.getInstance("TLSv1.0")
  // ruleid: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val serverSocketFactory = sslContext.getServerSocketFactory()
  val serverSocket = serverSocketFactory.createServerSocket(8443)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_13(): Unit = {
  // Using weak protocol in a custom SSLEngine configuration
  val sslContext = SSLContext.getInstance("TLS")
  // ruleid: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val engine = sslContext.createSSLEngine("example.com", 443)
  engine.setEnabledProtocols(Array("TLSv1.1", "TLSv1", "SSLv3"))
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_14(): Unit = {
  // Creating a custom socket with weak protocol
  val sslContext = SSLContext.getInstance("SSLv3")
  // ruleid: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val socketFactory = sslContext.getSocketFactory()
  val socket = socketFactory.createSocket("example.com", 443)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_15(): Unit = {
  // Using weak protocol with explicit protocol selection
  val sslContext = SSLContext.getInstance("TLS")
  // ruleid: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val sslParameters = sslContext.getDefaultSSLParameters
  sslParameters.setProtocols(Array("TLSv1"))
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

// True Negatives (Secure Code)

def good_case_1(): Unit = {
  // Creating an SSLContext with a secure protocol
  val sslContext = SSLContext.getInstance("TLSv1.2")
  // ok: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val sslSocketFactory = sslContext.getSocketFactory()
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_2(): Unit = {
  val sc = SSLContext.getInstance("TLSv1.3")
  // ok: scala-weak-tls-protocol
  sc.init(null, null, new SecureRandom())
  val sslSocketFactory = sc.getSocketFactory()
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_3(): Unit = {
  // Creating an HttpsURLConnection with secure protocol
  val url = new java.net.URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[javax.net.ssl.HttpsURLConnection]
  val sslContext = SSLContext.getInstance("TLSv1.2")
  // ok: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  connection.setSSLSocketFactory(sslContext.getSocketFactory())
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_4(): Unit = {
  // Using secure protocol with Apache HttpClient
  val sslContext = SSLContext.getInstance("TLSv1.2")
  // ok: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val sslsf = new SSLConnectionSocketFactory(
    sslContext,
    Array("TLSv1.2", "TLSv1.3"),
    null,
    SSLConnectionSocketFactory.getDefaultHostnameVerifier
  )
  val httpClient = HttpClients.custom().setSSLSocketFactory(sslsf).build()
}
// {/fact}

def good_case_5()(implicit system: ActorSystem): Future[HttpResponse] = {
  // Using secure protocol with Akka HTTP
  val sslContext = SSLContext.getInstance("TLSv1.2")
  // ok: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val https = ConnectionContext.httpsClient(sslContext)
  Http().singleRequest(
    HttpRequest(uri = "https://example.com"),
    https
  )
}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_6(): Unit = {
  // Creating custom SSLContext with only secure protocols
  val sslContext = SSLContext.getInstance("TLS")
  // ok: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val sslParameters = sslContext.getDefaultSSLParameters
  sslParameters.setProtocols(Array("TLSv1.2", "TLSv1.3"))
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_7(): Unit = {
  // Creating an SSLEngine with secure protocols
  val sslContext = SSLContext.getInstance("TLS")
  // ok: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val engine = sslContext.createSSLEngine()
  engine.setEnabledProtocols(Array("TLSv1.2", "TLSv1.3"))
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_8(): CloseableHttpClient = {
  // Creating Apache HttpClient with secure protocols
  val sslContext = SSLContexts.custom().build()
  // ok: scala-weak-tls-protocol
  val socketFactory = new SSLConnectionSocketFactory(
    sslContext,
    Array("TLSv1.2", "TLSv1.3"),
    null,
    SSLConnectionSocketFactory.getDefaultHostnameVerifier
  )
  HttpClients.custom().setSSLSocketFactory(socketFactory).build()
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_9(): Unit = {
  // Using secure protocol with default settings
  val sslContext = SSLContext.getInstance("TLSv1.2")
  // ok: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  // Default configuration will use secure protocols
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_10(): Unit = {
  // Using secure protocol with custom KeyManager
  val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm)
  val sslContext = SSLContext.getInstance("TLSv1.2")
  // ok: scala-weak-tls-protocol
  sslContext.init(keyManagerFactory.getKeyManagers, null, new SecureRandom())
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_11(): Unit = {
  // Using secure protocol with Play WS client
  val sslConfig = new play.api.libs.ws.ssl.Config.Builder()
    .withEnabledProtocols(Array("TLSv1.2", "TLSv1.3"))
    .build()
  
  // ok: scala-weak-tls-protocol
  val sslContext = SSLContext.getInstance("TLSv1.2")
  sslContext.init(null, null, new SecureRandom())
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_12(): Unit = {
  // Creating a server socket with secure protocol
  val sslContext = SSLContext.getInstance("TLSv1.2")
  // ok: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val serverSocketFactory = sslContext.getServerSocketFactory()
  val serverSocket = serverSocketFactory.createServerSocket(8443)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_13(): Unit = {
  // Using secure protocol in a custom SSLEngine configuration
  val sslContext = SSLContext.getInstance("TLS")
  // ok: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val engine = sslContext.createSSLEngine("example.com", 443)
  engine.setEnabledProtocols(Array("TLSv1.2", "TLSv1.3"))
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_14(): Unit = {
  // Creating a custom socket with secure protocol
  val sslContext = SSLContext.getInstance("TLSv1.2")
  // ok: scala-weak-tls-protocol
  sslContext.init(null, null, new SecureRandom())
  val socketFactory = sslContext.getSocketFactory()
  val socket = socketFactory.createSocket("example.com", 443)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_15(): Unit = {
  // Using default TLS which will use the most secure available protocol
  val sslContext = SSLContext.getDefault
  // ok: scala-weak-tls-protocol
  val sslSocketFactory = sslContext.getSocketFactory()
  // Default configuration will use secure protocols
}
// {/fact}