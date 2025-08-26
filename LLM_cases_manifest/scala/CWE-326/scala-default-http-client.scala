import org.apache.http.client.HttpClient
import org.apache.http.client.methods.{HttpGet, HttpPost}
import org.apache.http.impl.client.{DefaultHttpClient, HttpClientBuilder, CloseableHttpClient}
import org.apache.http.client.config.RequestConfig
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils
import org.apache.http.entity.StringEntity
import org.apache.http.client.entity.UrlEncodedFormEntity
import org.apache.http.message.BasicNameValuePair
import org.apache.http.NameValuePair
import java.util.ArrayList
import scala.collection.JavaConverters._
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import javax.net.ssl.SSLContext
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.ssl.SSLContexts
import org.apache.http.client.methods.CloseableHttpResponse
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// True Positives - Vulnerable code that should be detected

def bad_case_1(): Unit = {
  // ruleid: scala-default-http-client
  val httpClient = new DefaultHttpClient()
  val httpGet = new HttpGet("https://api.example.com/data")
  val response = httpClient.execute(httpGet)
  val entity = response.getEntity()
  val content = EntityUtils.toString(entity)
  println(content)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_2(): Unit = {
  // ruleid: scala-default-http-client
  val client = new DefaultHttpClient()
  val post = new HttpPost("https://api.example.com/submit")
  val nameValuePairs = new ArrayList[NameValuePair]()
  nameValuePairs.add(new BasicNameValuePair("username", "user123"))
  nameValuePairs.add(new BasicNameValuePair("password", "pass123"))
  post.setEntity(new UrlEncodedFormEntity(nameValuePairs))
  val response = client.execute(post)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_3(): Unit = {
  // Creating a function that returns DefaultHttpClient
  def createClient(): HttpClient = {
    // ruleid: scala-default-http-client
    new DefaultHttpClient()
  }
  
  val client = createClient()
  val get = new HttpGet("https://api.example.com/users")
  val response = client.execute(get)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_4(): Unit = {
  val url = "https://api.example.com/products"
  
  // ruleid: scala-default-http-client
  val httpClient = new DefaultHttpClient()
  try {
    val httpGet = new HttpGet(url)
    httpGet.setHeader("Accept", "application/json")
    val response = httpClient.execute(httpGet)
    val entity = response.getEntity()
    val content = EntityUtils.toString(entity)
    println(s"Response: $content")
  } finally {
    httpClient.getConnectionManager().shutdown()
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_5(): Unit = {
  // Using DefaultHttpClient with custom parameters
  // ruleid: scala-default-http-client
  val httpClient = new DefaultHttpClient()
  httpClient.getParams().setParameter("http.socket.timeout", 5000)
  httpClient.getParams().setParameter("http.connection.timeout", 5000)
  
  val httpGet = new HttpGet("https://api.example.com/timeout-test")
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_6(): Unit = {
  // Using DefaultHttpClient in a class
  class ApiClient {
    // ruleid: scala-default-http-client
    private val httpClient = new DefaultHttpClient()
    
    def fetchData(url: String): String = {
      val httpGet = new HttpGet(url)
      val response = httpClient.execute(httpGet)
      val entity = response.getEntity()
      EntityUtils.toString(entity)
    }
  }
  
  val client = new ApiClient()
  val data = client.fetchData("https://api.example.com/data")
  println(data)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_7(): Unit = {
  // Using DefaultHttpClient with try-catch
  try {
    // ruleid: scala-default-http-client
    val httpClient = new DefaultHttpClient()
    val httpGet = new HttpGet("https://api.example.com/error-prone")
    val response = httpClient.execute(httpGet)
    val entity = response.getEntity()
    val content = EntityUtils.toString(entity)
    println(content)
  } catch {
    case e: Exception => println(s"Error: ${e.getMessage}")
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_8(): Unit = {
  // Using DefaultHttpClient with a proxy
  // ruleid: scala-default-http-client
  val httpClient = new DefaultHttpClient()
  val httpGet = new HttpGet("https://api.example.com/proxy-test")
  
  // Setting proxy parameters
  httpClient.getParams().setParameter("http.route.default-proxy", 
    new org.apache.http.HttpHost("proxy.example.com", 8080))
  
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_9(): Unit = {
  // Using DefaultHttpClient with authentication
  // ruleid: scala-default-http-client
  val httpClient = new DefaultHttpClient()
  val httpGet = new HttpGet("https://api.example.com/secure")
  
  // Setting basic authentication
  val credentials = new org.apache.http.auth.UsernamePasswordCredentials("username", "password")
  httpClient.getCredentialsProvider().setCredentials(
    new org.apache.http.auth.AuthScope("api.example.com", 443), 
    credentials
  )
  
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_10(): Unit = {
  // Using DefaultHttpClient with custom user agent
  // ruleid: scala-default-http-client
  val httpClient = new DefaultHttpClient()
  val httpGet = new HttpGet("https://api.example.com/user-agent-test")
  
  // Setting user agent
  httpClient.getParams().setParameter("http.useragent", "Custom User Agent")
  
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_11(): Unit = {
  // Using DefaultHttpClient with POST and JSON payload
  // ruleid: scala-default-http-client
  val httpClient = new DefaultHttpClient()
  val httpPost = new HttpPost("https://api.example.com/json")
  
  val json = """{"name":"John","age":30,"city":"New York"}"""
  val entity = new StringEntity(json)
  httpPost.setEntity(entity)
  httpPost.setHeader("Content-type", "application/json")
  
  val response = httpClient.execute(httpPost)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_12(): Unit = {
  // Using DefaultHttpClient in a multi-threaded environment
  val runnable = new Runnable {
    override def run(): Unit = {
      // ruleid: scala-default-http-client
      val httpClient = new DefaultHttpClient()
      val httpGet = new HttpGet("https://api.example.com/thread-test")
      val response = httpClient.execute(httpGet)
      EntityUtils.consume(response.getEntity())
    }
  }
  
  val thread = new Thread(runnable)
  thread.start()
  thread.join()
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_13(): Unit = {
  // Using DefaultHttpClient with connection pooling
  // ruleid: scala-default-http-client
  val httpClient = new DefaultHttpClient()
  val connManager = httpClient.getConnectionManager()
  connManager.getSchemeRegistry().register(
    new org.apache.http.conn.scheme.Scheme("https", 443, 
      org.apache.http.conn.ssl.SSLSocketFactory.getSocketFactory())
  )
  
  val httpGet = new HttpGet("https://api.example.com/pool-test")
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_14(): Unit = {
  // Using DefaultHttpClient with custom timeout settings
  // ruleid: scala-default-http-client
  val httpClient = new DefaultHttpClient()
  val params = httpClient.getParams()
  params.setIntParameter(org.apache.http.params.CoreConnectionPNames.CONNECTION_TIMEOUT, 3000)
  params.setIntParameter(org.apache.http.params.CoreConnectionPNames.SO_TIMEOUT, 5000)
  
  val httpGet = new HttpGet("https://api.example.com/timeout")
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

def bad_case_15(): Unit = {
  // Using DefaultHttpClient with retry handler
  // ruleid: scala-default-http-client
  val httpClient = new DefaultHttpClient()
  httpClient.setHttpRequestRetryHandler(new org.apache.http.impl.client.DefaultHttpRequestRetryHandler(3, true))
  
  val httpGet = new HttpGet("https://api.example.com/retry-test")
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// True Negatives - Safe code that should not be detected

def good_case_1(): Unit = {
  // ok: scala-default-http-client
  val httpClient = HttpClientBuilder.create().build()
  val httpGet = new HttpGet("https://api.example.com/data")
  val response = httpClient.execute(httpGet)
  val entity = response.getEntity()
  val content = EntityUtils.toString(entity)
  println(content)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_2(): Unit = {
  // ok: scala-default-http-client
  val httpClient = HttpClients.createDefault()
  val post = new HttpPost("https://api.example.com/submit")
  val nameValuePairs = new ArrayList[NameValuePair]()
  nameValuePairs.add(new BasicNameValuePair("username", "user123"))
  nameValuePairs.add(new BasicNameValuePair("password", "pass123"))
  post.setEntity(new UrlEncodedFormEntity(nameValuePairs))
  val response = httpClient.execute(post)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_3(): Unit = {
  // Creating a function that returns a modern HttpClient
  def createClient(): CloseableHttpClient = {
    // ok: scala-default-http-client
    HttpClientBuilder.create().build()
  }
  
  val client = createClient()
  val get = new HttpGet("https://api.example.com/users")
  val response = client.execute(get)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_4(): Unit = {
  val url = "https://api.example.com/products"
  
  // ok: scala-default-http-client
  val httpClient = HttpClients.custom()
    .setMaxConnTotal(100)
    .setMaxConnPerRoute(20)
    .build()
  
  try {
    val httpGet = new HttpGet(url)
    httpGet.setHeader("Accept", "application/json")
    val response = httpClient.execute(httpGet)
    val entity = response.getEntity()
    val content = EntityUtils.toString(entity)
    println(s"Response: $content")
  } finally {
    httpClient.close()
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_5(): Unit = {
  // Using HttpClientBuilder with custom parameters
  // ok: scala-default-http-client
  val requestConfig = RequestConfig.custom()
    .setConnectTimeout(5000)
    .setSocketTimeout(5000)
    .build()
  
  val httpClient = HttpClientBuilder.create()
    .setDefaultRequestConfig(requestConfig)
    .build()
  
  val httpGet = new HttpGet("https://api.example.com/timeout-test")
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_6(): Unit = {
  // Using HttpClientBuilder in a class
  class ApiClient {
    // ok: scala-default-http-client
    private val httpClient = HttpClientBuilder.create().build()
    
    def fetchData(url: String): String = {
      val httpGet = new HttpGet(url)
      val response = httpClient.execute(httpGet)
      val entity = response.getEntity()
      EntityUtils.toString(entity)
    }
  }
  
  val client = new ApiClient()
  val data = client.fetchData("https://api.example.com/data")
  println(data)
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_7(): Unit = {
  // Using HttpClientBuilder with try-catch
  try {
    // ok: scala-default-http-client
    val httpClient = HttpClients.createDefault()
    val httpGet = new HttpGet("https://api.example.com/error-prone")
    val response = httpClient.execute(httpGet)
    val entity = response.getEntity()
    val content = EntityUtils.toString(entity)
    println(content)
  } catch {
    case e: Exception => println(s"Error: ${e.getMessage}")
  }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_8(): Unit = {
  // Using HttpClientBuilder with a proxy
  // ok: scala-default-http-client
  val httpClient = HttpClientBuilder.create()
    .setProxy(new org.apache.http.HttpHost("proxy.example.com", 8080))
    .build()
  
  val httpGet = new HttpGet("https://api.example.com/proxy-test")
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_9(): Unit = {
  // Using HttpClientBuilder with authentication
  // ok: scala-default-http-client
  val credentialsProvider = new org.apache.http.impl.client.BasicCredentialsProvider()
  credentialsProvider.setCredentials(
    new org.apache.http.auth.AuthScope("api.example.com", 443),
    new org.apache.http.auth.UsernamePasswordCredentials("username", "password")
  )
  
  val httpClient = HttpClientBuilder.create()
    .setDefaultCredentialsProvider(credentialsProvider)
    .build()
  
  val httpGet = new HttpGet("https://api.example.com/secure")
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_10(): Unit = {
  // Using HttpClientBuilder with custom user agent
  // ok: scala-default-http-client
  val httpClient = HttpClientBuilder.create()
    .setUserAgent("Custom User Agent")
    .build()
  
  val httpGet = new HttpGet("https://api.example.com/user-agent-test")
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_11(): Unit = {
  // Using HttpClientBuilder with POST and JSON payload
  // ok: scala-default-http-client
  val httpClient = HttpClients.createDefault()
  val httpPost = new HttpPost("https://api.example.com/json")
  
  val json = """{"name":"John","age":30,"city":"New York"}"""
  val entity = new StringEntity(json)
  httpPost.setEntity(entity)
  httpPost.setHeader("Content-type", "application/json")
  
  val response = httpClient.execute(httpPost)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_12(): Unit = {
  // Using HttpClientBuilder in a multi-threaded environment
  val runnable = new Runnable {
    override def run(): Unit = {
      // ok: scala-default-http-client
      val httpClient = HttpClients.createDefault()
      val httpGet = new HttpGet("https://api.example.com/thread-test")
      val response = httpClient.execute(httpGet)
      EntityUtils.consume(response.getEntity())
    }
  }
  
  val thread = new Thread(runnable)
  thread.start()
  thread.join()
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_13(): Unit = {
  // Using HttpClientBuilder with SSL context
  // ok: scala-default-http-client
  val sslContext = SSLContexts.custom()
    .loadTrustMaterial(null, new TrustSelfSignedStrategy())
    .build()
  
  val sslSocketFactory = new SSLConnectionSocketFactory(
    sslContext, Array("TLSv1.2"), null, SSLConnectionSocketFactory.getDefaultHostnameVerifier()
  )
  
  val httpClient = HttpClients.custom()
    .setSSLSocketFactory(sslSocketFactory)
    .build()
  
  val httpGet = new HttpGet("https://api.example.com/ssl-test")
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_14(): Unit = {
  // Using HttpClientBuilder with custom timeout settings
  // ok: scala-default-http-client
  val requestConfig = RequestConfig.custom()
    .setConnectTimeout(3000)
    .setSocketTimeout(5000)
    .build()
  
  val httpClient = HttpClientBuilder.create()
    .setDefaultRequestConfig(requestConfig)
    .build()
  
  val httpGet = new HttpGet("https://api.example.com/timeout")
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

def good_case_15(): Unit = {
  // Using HttpClientBuilder with retry handler
  // ok: scala-default-http-client
  val httpClient = HttpClientBuilder.create()
    .setRetryHandler(new org.apache.http.impl.client.DefaultHttpRequestRetryHandler(3, true))
    .build()
  
  val httpGet = new HttpGet("https://api.example.com/retry-test")
  val response = httpClient.execute(httpGet)
  EntityUtils.consume(response.getEntity())
}
// {/fact}