import java.net.URL
import javax.net.ssl._
import java.security.cert.X509Certificate
import scala.io.Source
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Try, Success, Failure}
import java.io.{FileInputStream, File}
import java.security.{KeyStore, SecureRandom}
import javax.net.ssl.{TrustManagerFactory, SSLContext}
import java.security.cert.CertificateException
// {fact rule=improper-certificate-validation@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(): Unit = {
  // Creating a trust manager that accepts all certificates
  val trustAllCerts = Array[TrustManager](new X509TrustManager() {
    override def getAcceptedIssuers: Array[X509Certificate] = null
    override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
    // ruleid: scala-weak-hostname-verification
    override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
  })

  val sc = SSLContext.getInstance("SSL")
  sc.init(null, trustAllCerts, new SecureRandom())
  HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory)
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_2(): Unit = {
  // Creating a hostname verifier that accepts all hostnames
  val allHostsValid = new HostnameVerifier() {
    // ruleid: scala-weak-hostname-verification
    override def verify(hostname: String, session: SSLSession): Boolean = true
  }
  
  HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid)
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_3(): Unit = {
  class TrustAllManager extends X509TrustManager {
    override def getAcceptedIssuers: Array[X509Certificate] = Array[X509Certificate]()
    override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
    // ruleid: scala-weak-hostname-verification
    override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
  }
  
  val sslContext = SSLContext.getInstance("TLS")
  sslContext.init(null, Array[TrustManager](new TrustAllManager()), null)
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sslContext.getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_4(): Unit = {
  // Custom hostname verifier that always returns true
  val hostnameVerifier = new HostnameVerifier {
    // ruleid: scala-weak-hostname-verification
    def verify(hostname: String, session: SSLSession): Boolean = {
      println(s"Verifying hostname: $hostname")
      return true // Always accepting any hostname
    }
  }
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setHostnameVerifier(hostnameVerifier)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_5(): Unit = {
  def makeRequest(url: String): String = {
    val trustAllCerts = Array[TrustManager](new X509TrustManager {
      override def getAcceptedIssuers: Array[X509Certificate] = null
      override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
      // ruleid: scala-weak-hostname-verification
      override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
    })
    
    val sc = SSLContext.getInstance("TLS")
    sc.init(null, trustAllCerts, new SecureRandom())
    
    val connection = new URL(url).openConnection().asInstanceOf[HttpsURLConnection]
    connection.setSSLSocketFactory(sc.getSocketFactory)
    Source.fromInputStream(connection.getInputStream).mkString
  }
  
  val response = makeRequest("https://example.com")
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_6(): Unit = {
  // Using a named class for trust manager
  class InsecureTrustManager extends X509TrustManager {
    override def getAcceptedIssuers: Array[X509Certificate] = Array.empty
    override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
    // ruleid: scala-weak-hostname-verification
    override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
  }
  
  val sslContext = SSLContext.getInstance("TLS")
  sslContext.init(null, Array[TrustManager](new InsecureTrustManager()), new SecureRandom())
  
  val connection = new URL("https://example.com").openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sslContext.getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_7(): Unit = {
  // Combining both insecure trust manager and hostname verifier
  val trustAllCerts = Array[TrustManager](new X509TrustManager {
    override def getAcceptedIssuers: Array[X509Certificate] = null
    override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
    // ruleid: scala-weak-hostname-verification
    override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
  })
  
  val sc = SSLContext.getInstance("TLS")
  sc.init(null, trustAllCerts, new SecureRandom())
  
  val connection = new URL("https://example.com").openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sc.getSocketFactory)
  connection.setHostnameVerifier((_, _) => true)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_8(): Unit = {
  // Using a function to create the insecure SSL context
  def createInsecureSSLContext(): SSLContext = {
    val trustAllCerts = Array[TrustManager](new X509TrustManager {
      override def getAcceptedIssuers: Array[X509Certificate] = null
      override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
      // ruleid: scala-weak-hostname-verification
      override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
    })
    
    val sc = SSLContext.getInstance("TLS")
    sc.init(null, trustAllCerts, new SecureRandom())
    sc
  }
  
  val connection = new URL("https://example.com").openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(createInsecureSSLContext().getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_9(): Unit = {
  // Using a more descriptive but still insecure hostname verifier
  val permissiveVerifier = new HostnameVerifier {
    // ruleid: scala-weak-hostname-verification
    override def verify(hostname: String, session: SSLSession): Boolean = {
      println(s"Connection to $hostname established, bypassing verification")
      true // Accepting any hostname without verification
    }
  }
  
  val connection = new URL("https://example.com").openConnection().asInstanceOf[HttpsURLConnection]
  connection.setHostnameVerifier(permissiveVerifier)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_10(): Unit = {
  // Using Future for async request with insecure SSL
  def fetchUrlAsync(url: String): Future[String] = Future {
    val trustAllCerts = Array[TrustManager](new X509TrustManager {
      override def getAcceptedIssuers: Array[X509Certificate] = null
      override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
      // ruleid: scala-weak-hostname-verification
      override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
    })
    
    val sc = SSLContext.getInstance("TLS")
    sc.init(null, trustAllCerts, new SecureRandom())
    
    val connection = new URL(url).openConnection().asInstanceOf[HttpsURLConnection]
    connection.setSSLSocketFactory(sc.getSocketFactory)
    Source.fromInputStream(connection.getInputStream).mkString
  }
  
  val futureResponse = fetchUrlAsync("https://example.com")
  futureResponse.onComplete {
    case Success(response) => println(s"Response: $response")
    case Failure(e) => println(s"Error: ${e.getMessage}")
  }
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_11(): Unit = {
  // Using a trust manager that logs but still accepts all certificates
  val loggingTrustAllManager = new X509TrustManager {
    override def getAcceptedIssuers: Array[X509Certificate] = Array.empty
    override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      println("Client certificate check bypassed")
    }
    // ruleid: scala-weak-hostname-verification
    override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      println("Server certificate check bypassed")
      // No actual verification is performed
    }
  }
  
  val sslContext = SSLContext.getInstance("TLS")
  sslContext.init(null, Array[TrustManager](loggingTrustAllManager), new SecureRandom())
  
  val connection = new URL("https://example.com").openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sslContext.getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_12(): Unit = {
  // Using a hostname verifier that only checks for specific domains but accepts all others
  val partialVerifier = new HostnameVerifier {
    // ruleid: scala-weak-hostname-verification
    override def verify(hostname: String, session: SSLSession): Boolean = {
      if (hostname == "malicious-site.com") {
        false
      } else {
        true // Still insecure for all other domains
      }
    }
  }
  
  val connection = new URL("https://example.com").openConnection().asInstanceOf[HttpsURLConnection]
  connection.setHostnameVerifier(partialVerifier)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_13(): Unit = {
  // Using a trust manager factory but still bypassing verification
  val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
  trustManagerFactory.init(null.asInstanceOf[KeyStore])
  
  val defaultTrustManagers = trustManagerFactory.getTrustManagers
  val wrappedTrustManagers = defaultTrustManagers.map {
    case x: X509TrustManager => new X509TrustManager {
      override def getAcceptedIssuers: Array[X509Certificate] = x.getAcceptedIssuers
      override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = 
        x.checkClientTrusted(certs, authType)
      // ruleid: scala-weak-hostname-verification
      override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {
        // Bypassing server certificate verification
      }
    }
    case tm => tm
  }
  
  val sslContext = SSLContext.getInstance("TLS")
  sslContext.init(null, wrappedTrustManagers, new SecureRandom())
  
  val connection = new URL("https://example.com").openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sslContext.getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_14(): Unit = {
  // Creating a trust manager that attempts to validate but catches and ignores all exceptions
  val catchAllTrustManager = new X509TrustManager {
    override def getAcceptedIssuers: Array[X509Certificate] = Array.empty
    override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {}
    // ruleid: scala-weak-hostname-verification
    override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      try {
        // Attempt to do some validation
        if (certs == null || certs.length == 0) {
          throw new CertificateException("No certificates provided")
        }
        // But catch and ignore any exceptions, effectively bypassing validation
      } catch {
        case _: Exception => // Ignore all exceptions
      }
    }
  }
  
  val sslContext = SSLContext.getInstance("TLS")
  sslContext.init(null, Array[TrustManager](catchAllTrustManager), new SecureRandom())
  
  val connection = new URL("https://example.com").openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sslContext.getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=1}

def bad_case_15(): Unit = {
  // Using a hostname verifier with a whitelist approach but with a default accept
  val whitelistVerifier = new HostnameVerifier {
    val whitelist = Set("trusted-domain.com", "another-trusted.org")
    
    // ruleid: scala-weak-hostname-verification
    override def verify(hostname: String, session: SSLSession): Boolean = {
      if (whitelist.contains(hostname)) {
        // Perform actual verification for whitelisted domains
        val defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier
        defaultVerifier.verify(hostname, session)
      } else {
        // Insecurely accept all other domains
        true
      }
    }
  }
  
  val connection = new URL("https://example.com").openConnection().asInstanceOf[HttpsURLConnection]
  connection.setHostnameVerifier(whitelistVerifier)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

// True Negative Examples (Secure Code)

def good_case_1(): Unit = {
  // Using the default SSL socket factory which performs proper verification
  // ok: scala-weak-hostname-verification
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_2(): Unit = {
  // Using a custom trust manager that properly delegates to the default implementation
  val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
  trustManagerFactory.init(null.asInstanceOf[KeyStore])
  
  // ok: scala-weak-hostname-verification
  val sslContext = SSLContext.getInstance("TLS")
  sslContext.init(null, trustManagerFactory.getTrustManagers, new SecureRandom())
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sslContext.getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_3(): Unit = {
  // Using a custom trust store for certificate validation
  val trustStore = KeyStore.getInstance(KeyStore.getDefaultType)
  val trustStoreFile = new FileInputStream("truststore.jks")
  try {
    trustStore.load(trustStoreFile, "password".toCharArray)
  } finally {
    trustStoreFile.close()
  }
  
  val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
  // ok: scala-weak-hostname-verification
  trustManagerFactory.init(trustStore)
  
  val sslContext = SSLContext.getInstance("TLS")
  sslContext.init(null, trustManagerFactory.getTrustManagers, new SecureRandom())
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sslContext.getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_4(): Unit = {
  // Using a hostname verifier that properly verifies hostnames
  val strictVerifier = new HostnameVerifier {
    // ok: scala-weak-hostname-verification
    override def verify(hostname: String, session: SSLSession): Boolean = {
      val defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier
      defaultVerifier.verify(hostname, session)
    }
  }
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setHostnameVerifier(strictVerifier)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_5(): Unit = {
  // Using a custom trust manager that performs proper validation
  val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
  trustManagerFactory.init(null.asInstanceOf[KeyStore])
  
  val defaultTrustManager = trustManagerFactory.getTrustManagers.find(_.isInstanceOf[X509TrustManager])
    .map(_.asInstanceOf[X509TrustManager])
    .getOrElse(throw new Exception("No X509TrustManager found"))
  
  val customTrustManager = new X509TrustManager {
    override def getAcceptedIssuers: Array[X509Certificate] = defaultTrustManager.getAcceptedIssuers
    
    override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      defaultTrustManager.checkClientTrusted(certs, authType)
    }
    
    // ok: scala-weak-hostname-verification
    override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      defaultTrustManager.checkServerTrusted(certs, authType)
      // Additional custom validation could be added here
    }
  }
  
  val sslContext = SSLContext.getInstance("TLS")
  sslContext.init(null, Array[TrustManager](customTrustManager), new SecureRandom())
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sslContext.getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_6(): Unit = {
  // Using Future for async request with proper SSL verification
  def fetchUrlAsync(url: String): Future[String] = Future {
    // ok: scala-weak-hostname-verification
    val connection = new URL(url).openConnection().asInstanceOf[HttpsURLConnection]
    // Using default SSL socket factory which performs proper verification
    Source.fromInputStream(connection.getInputStream).mkString
  }
  
  val futureResponse = fetchUrlAsync("https://example.com")
  futureResponse.onComplete {
    case Success(response) => println(s"Response: $response")
    case Failure(e) => println(s"Error: ${e.getMessage}")
  }
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_7(): Unit = {
  // Using a hostname verifier that implements proper domain-specific checks
  val domainVerifier = new HostnameVerifier {
    // ok: scala-weak-hostname-verification
    override def verify(hostname: String, session: SSLSession): Boolean = {
      // First use the default verifier for standard checks
      val defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier
      val standardVerification = defaultVerifier.verify(hostname, session)
      
      if (!standardVerification) {
        false
      } else {
        // Additional domain-specific verification
        hostname.endsWith(".com") || hostname.endsWith(".org")
      }
    }
  }
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setHostnameVerifier(domainVerifier)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_8(): Unit = {
  // Using a trust manager that performs additional certificate validation
  val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
  trustManagerFactory.init(null.asInstanceOf[KeyStore])
  
  val defaultTrustManager = trustManagerFactory.getTrustManagers.find(_.isInstanceOf[X509TrustManager])
    .map(_.asInstanceOf[X509TrustManager])
    .getOrElse(throw new Exception("No X509TrustManager found"))
  
  val enhancedTrustManager = new X509TrustManager {
    override def getAcceptedIssuers: Array[X509Certificate] = defaultTrustManager.getAcceptedIssuers
    
    override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      defaultTrustManager.checkClientTrusted(certs, authType)
    }
    
    // ok: scala-weak-hostname-verification
    override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      defaultTrustManager.checkServerTrusted(certs, authType)
      
      // Additional validation: check certificate expiration date
      val now = System.currentTimeMillis()
      certs.foreach { cert =>
        if (cert.getNotAfter.getTime < now || cert.getNotBefore.getTime > now) {
          throw new CertificateException("Certificate is not valid at the current time")
        }
      }
    }
  }
  
  val sslContext = SSLContext.getInstance("TLS")
  sslContext.init(null, Array[TrustManager](enhancedTrustManager), new SecureRandom())
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sslContext.getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_9(): Unit = {
  // Using a custom SSL context with proper certificate validation
  def createSecureSSLContext(): SSLContext = {
    // ok: scala-weak-hostname-verification
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    trustManagerFactory.init(null.asInstanceOf[KeyStore])
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustManagerFactory.getTrustManagers, new SecureRandom())
    sslContext
  }
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(createSecureSSLContext().getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_10(): Unit = {
  // Using a custom trust manager that logs certificate details but still performs proper validation
  val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
  trustManagerFactory.init(null.asInstanceOf[KeyStore])
  
  val defaultTrustManager = trustManagerFactory.getTrustManagers.find(_.isInstanceOf[X509TrustManager])
    .map(_.asInstanceOf[X509TrustManager])
    .getOrElse(throw new Exception("No X509TrustManager found"))
  
  val loggingTrustManager = new X509TrustManager {
    override def getAcceptedIssuers: Array[X509Certificate] = defaultTrustManager.getAcceptedIssuers
    
    override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      defaultTrustManager.checkClientTrusted(certs, authType)
    }
    
    // ok: scala-weak-hostname-verification
    override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      println(s"Validating server certificate with auth type: $authType")
      certs.foreach(cert => println(s"Certificate subject: ${cert.getSubjectX500Principal.getName}"))
      
      // Properly delegate to default trust manager for actual validation
      defaultTrustManager.checkServerTrusted(certs, authType)
    }
  }
  
  val sslContext = SSLContext.getInstance("TLS")
  sslContext.init(null, Array[TrustManager](loggingTrustManager), new SecureRandom())
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sslContext.getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_11(): Unit = {
  // Using a hostname verifier with a whitelist approach that falls back to default verification
  val whitelistVerifier = new HostnameVerifier {
    val whitelist = Set("trusted-domain.com", "another-trusted.org")
    
    // ok: scala-weak-hostname-verification
    override def verify(hostname: String, session: SSLSession): Boolean = {
      if (whitelist.contains(hostname)) {
        true // Accept whitelisted domains
      } else {
        // For all other domains, use default verification
        val defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier
        defaultVerifier.verify(hostname, session)
      }
    }
  }
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setHostnameVerifier(whitelistVerifier)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_12(): Unit = {
  // Loading a custom trust store from a file with proper error handling
  def loadTrustStore(path: String, password: String): KeyStore = {
    val trustStore = KeyStore.getInstance(KeyStore.getDefaultType)
    val trustStoreFile = new FileInputStream(path)
    try {
      trustStore.load(trustStoreFile, password.toCharArray)
      trustStore
    } finally {
      trustStoreFile.close()
    }
  }
  
  try {
    val trustStore = loadTrustStore("truststore.jks", "password")
    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    // ok: scala-weak-hostname-verification
    trustManagerFactory.init(trustStore)
    
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustManagerFactory.getTrustManagers, new SecureRandom())
    
    val url = new URL("https://example.com")
    val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
    connection.setSSLSocketFactory(sslContext.getSocketFactory)
    val response = Source.fromInputStream(connection.getInputStream).mkString
    println(response)
  } catch {
    case e: Exception => println(s"Error setting up SSL context: ${e.getMessage}")
  }
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_13(): Unit = {
  // Using a trust manager that validates certificate pinning
  val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
  trustManagerFactory.init(null.asInstanceOf[KeyStore])
  
  val defaultTrustManager = trustManagerFactory.getTrustManagers.find(_.isInstanceOf[X509TrustManager])
    .map(_.asInstanceOf[X509TrustManager])
    .getOrElse(throw new Exception("No X509TrustManager found"))
  
  // Expected certificate fingerprints for certificate pinning
  val expectedFingerprints = Set(
    "44:14:B5:15:C5:FB:D5:9A:11:5C:24:38:43:50:2D:F5:BE:6C:0F:D3"
  )
  
  val pinningTrustManager = new X509TrustManager {
    override def getAcceptedIssuers: Array[X509Certificate] = defaultTrustManager.getAcceptedIssuers
    
    override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      defaultTrustManager.checkClientTrusted(certs, authType)
    }
    
    // ok: scala-weak-hostname-verification
    override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      // First perform standard certificate validation
      defaultTrustManager.checkServerTrusted(certs, authType)
      
      // Then perform certificate pinning
      val messageDigest = java.security.MessageDigest.getInstance("SHA-1")
      val fingerprint = certs(0).getEncoded
      val digest = messageDigest.digest(fingerprint)
      val hexString = digest.map("%02X".format(_)).mkString(":")
      
      if (!expectedFingerprints.contains(hexString)) {
        throw new CertificateException("Certificate pinning validation failed")
      }
    }
  }
  
  val sslContext = SSLContext.getInstance("TLS")
  sslContext.init(null, Array[TrustManager](pinningTrustManager), new SecureRandom())
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sslContext.getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_14(): Unit = {
  // Using a trust manager that validates certificate revocation status
  val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
  trustManagerFactory.init(null.asInstanceOf[KeyStore])
  
  val defaultTrustManager = trustManagerFactory.getTrustManagers.find(_.isInstanceOf[X509TrustManager])
    .map(_.asInstanceOf[X509TrustManager])
    .getOrElse(throw new Exception("No X509TrustManager found"))
  
  val revocationCheckingTrustManager = new X509TrustManager {
    override def getAcceptedIssuers: Array[X509Certificate] = defaultTrustManager.getAcceptedIssuers
    
    override def checkClientTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      defaultTrustManager.checkClientTrusted(certs, authType)
    }
    
    // ok: scala-weak-hostname-verification
    override def checkServerTrusted(certs: Array[X509Certificate], authType: String): Unit = {
      // First perform standard certificate validation
      defaultTrustManager.checkServerTrusted(certs, authType)
      
      // Check certificate revocation status
      // This is a simplified example - in a real implementation you would check
      // against OCSP or CRL
      for (cert <- certs) {
        if (cert.getCriticalExtensionOIDs != null && 
            cert.getCriticalExtensionOIDs.contains("2.5.29.15")) {
          val keyUsage = cert.getKeyUsage
          if (keyUsage != null && keyUsage(0)) {
            // This certificate has digital signature capability
            // In a real implementation, you would check revocation status here
          }
        }
      }
    }
  }
  
  val sslContext = SSLContext.getInstance("TLS")
  sslContext.init(null, Array[TrustManager](revocationCheckingTrustManager), new SecureRandom())
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  connection.setSSLSocketFactory(sslContext.getSocketFactory)
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}
// {fact rule=improper-certificate-validation@v1.0 defects=0}

def good_case_15(): Unit = {
  // Using system properties to configure proper SSL validation
  // ok: scala-weak-hostname-verification
  System.setProperty("https.protocols", "TLSv1.2,TLSv1.3")
  System.setProperty("jdk.tls.client.protocols", "TLSv1.2,TLSv1.3")
  System.setProperty("https.cipherSuites", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
  
  val url = new URL("https://example.com")
  val connection = url.openConnection().asInstanceOf[HttpsURLConnection]
  
  // Enable hostname verification
  connection.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier)
  
  val response = Source.fromInputStream(connection.getInputStream).mkString
  println(response)
}
// {/fact}