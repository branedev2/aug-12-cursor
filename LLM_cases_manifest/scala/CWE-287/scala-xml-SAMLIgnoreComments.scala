import org.opensaml.xml.parse.BasicParserPool
import org.opensaml.xml.parse.ParserPool
import org.opensaml.xml.Configuration
import org.opensaml.DefaultBootstrap
import org.opensaml.saml2.core.Response
import org.opensaml.xml.io.Unmarshaller
import org.opensaml.xml.io.UnmarshallerFactory
import org.opensaml.xml.parse.StaticBasicParserPool
import org.opensaml.xml.security.SecurityHelper
import org.opensaml.xml.signature.SignatureValidator
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.HashMap
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Document
import org.w3c.dom.Element
import scala.collection.JavaConverters._
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(): Unit = {
  // Creating a BasicParserPool without setting ignoreComments to true
  val parserPool = new BasicParserPool()
  // ruleid: scala-xml-SAMLIgnoreComments
  parserPool.setIgnoreComments(false)
  
  // Use the parser pool for SAML processing
  val documentBuilder = parserPool.getBuilder()
  val document = documentBuilder.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_2(): Unit = {
  // Creating a BasicParserPool with default settings (ignoreComments is false by default)
  val parserPool = new BasicParserPool()
  
  // ruleid: scala-xml-SAMLIgnoreComments
  val features = new HashMap[String, Boolean]()
  parserPool.setBuilderFeatures(features)
  
  // Use the parser pool for SAML processing
  val documentBuilder = parserPool.getBuilder()
  val document = documentBuilder.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_3(): Unit = {
  // Initializing OpenSAML
  DefaultBootstrap.bootstrap()
  
  // Creating a BasicParserPool and explicitly setting ignoreComments to false
  val parserPool = new BasicParserPool()
  // ruleid: scala-xml-SAMLIgnoreComments
  parserPool.setIgnoreComments(false)
  parserPool.initialize()
  
  // Use for SAML response parsing
  val samlResponse = "<saml:Response><!-- Comment --></saml:Response>"
  val inputStream = new ByteArrayInputStream(samlResponse.getBytes())
  val document = parserPool.parse(inputStream)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_4(): Unit = {
  // Creating a StaticBasicParserPool without setting ignoreComments
  val parserPool = new StaticBasicParserPool()
  
  // ruleid: scala-xml-SAMLIgnoreComments
  val features = new HashMap[String, Boolean]()
  features.put("http://apache.org/xml/features/disallow-doctype-decl", true)
  features.put("http://xml.org/sax/features/external-general-entities", false)
  parserPool.setBuilderFeatures(features)
  
  // Initialize and use for SAML
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_5(): Unit = {
  // Configure parser pool for SAML processing
  val parserPool = new BasicParserPool()
  // ruleid: scala-xml-SAMLIgnoreComments
  val features = new HashMap[String, Boolean]()
  features.put("http://apache.org/xml/features/disallow-doctype-decl", true)
  features.put("http://xml.org/sax/features/external-general-entities", false)
  features.put("http://xml.org/sax/features/external-parameter-entities", false)
  parserPool.setBuilderFeatures(features)
  // No ignoreComments setting
  
  // Use for SAML
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_6(): Unit = {
  // Creating a custom SAML processor with BasicParserPool
  class SAMLProcessor {
    private val parserPool = new BasicParserPool()
    
    def initialize(): Unit = {
      // ruleid: scala-xml-SAMLIgnoreComments
      parserPool.setIgnoreComments(false)
      parserPool.initialize()
    }
    
    def processSAMLResponse(samlResponse: String): Document = {
      val inputStream = new ByteArrayInputStream(samlResponse.getBytes())
      parserPool.parse(inputStream)
    }
  }
  
  val processor = new SAMLProcessor()
  processor.initialize()
  processor.processSAMLResponse("<saml:Response><!-- Comment --></saml:Response>")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_7(): Unit = {
  // Factory method creating parser pool for SAML
  def createSAMLParserPool(): ParserPool = {
    val pool = new BasicParserPool()
    // ruleid: scala-xml-SAMLIgnoreComments
    // Not setting ignoreComments at all (defaults to false)
    pool.initialize()
    pool
  }
  
  val parserPool = createSAMLParserPool()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_8(): Unit = {
  // SAML configuration with multiple parser settings but missing ignoreComments
  val parserPool = new BasicParserPool()
  
  // ruleid: scala-xml-SAMLIgnoreComments
  parserPool.setMaxPoolSize(100)
  parserPool.setCoalescing(true)
  parserPool.setExpandEntityReferences(false)
  parserPool.setNamespaceAware(true)
  // Missing ignoreComments = true
  
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_9(): Unit = {
  // SAML processor with conditional configuration
  val parserPool = new BasicParserPool()
  val isSecureMode = false
  
  if (isSecureMode) {
    parserPool.setIgnoreComments(true)
  } else {
    // ruleid: scala-xml-SAMLIgnoreComments
    parserPool.setIgnoreComments(false)
  }
  
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_10(): Unit = {
  // SAML configuration with dynamic settings
  def configureSAMLParser(ignoreComments: Boolean): ParserPool = {
    val parserPool = new BasicParserPool()
    // ruleid: scala-xml-SAMLIgnoreComments
    parserPool.setIgnoreComments(ignoreComments)
    parserPool.initialize()
    parserPool
  }
  
  // Calling with false
  val parserPool = configureSAMLParser(false)
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_11(): Unit = {
  // SAML processor with environment-based configuration
  val parserPool = new BasicParserPool()
  val env = "development"
  
  if (env == "production") {
    parserPool.setIgnoreComments(true)
  } else {
    // ruleid: scala-xml-SAMLIgnoreComments
    // In development, not ignoring comments
    parserPool.setIgnoreComments(false)
  }
  
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_12(): Unit = {
  // SAML configuration with builder pattern
  class SAMLParserBuilder {
    private val parserPool = new BasicParserPool()
    
    def withNamespaceAware(value: Boolean): SAMLParserBuilder = {
      parserPool.setNamespaceAware(value)
      this
    }
    
    def withIgnoreComments(value: Boolean): SAMLParserBuilder = {
      // ruleid: scala-xml-SAMLIgnoreComments
      parserPool.setIgnoreComments(value)
      this
    }
    
    def build(): ParserPool = {
      parserPool.initialize()
      parserPool
    }
  }
  
  val parserPool = new SAMLParserBuilder()
    .withNamespaceAware(true)
    .withIgnoreComments(false)
    .build()
    
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_13(): Unit = {
  // SAML configuration with feature map
  val parserPool = new BasicParserPool()
  
  // ruleid: scala-xml-SAMLIgnoreComments
  val features = Map(
    "http://apache.org/xml/features/disallow-doctype-decl" -> true,
    "http://xml.org/sax/features/external-general-entities" -> false
  )
  
  val javaFeatures = new HashMap[String, Boolean]()
  features.foreach { case (key, value) => javaFeatures.put(key, value) }
  parserPool.setBuilderFeatures(javaFeatures)
  // Missing ignoreComments setting
  
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_14(): Unit = {
  // SAML configuration with explicit setting of multiple properties
  val parserPool = new BasicParserPool()
  
  // ruleid: scala-xml-SAMLIgnoreComments
  parserPool.setNamespaceAware(true)
  parserPool.setCoalescing(false)
  parserPool.setExpandEntityReferences(false)
  parserPool.setIgnoreComments(false) // Explicitly setting to false
  
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

def bad_case_15(): Unit = {
  // SAML configuration with configuration object
  class SAMLConfig {
    var namespaceAware: Boolean = true
    var ignoreComments: Boolean = false
    var expandEntityReferences: Boolean = false
  }
  
  def configureSAMLParser(config: SAMLConfig): ParserPool = {
    val parserPool = new BasicParserPool()
    parserPool.setNamespaceAware(config.namespaceAware)
    // ruleid: scala-xml-SAMLIgnoreComments
    parserPool.setIgnoreComments(config.ignoreComments)
    parserPool.setExpandEntityReferences(config.expandEntityReferences)
    parserPool.initialize()
    parserPool
  }
  
  val config = new SAMLConfig()
  val parserPool = configureSAMLParser(config)
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// True Negatives (Secure Code)

def good_case_1(): Unit = {
  // Creating a BasicParserPool with ignoreComments set to true
  val parserPool = new BasicParserPool()
  // ok: scala-xml-SAMLIgnoreComments
  parserPool.setIgnoreComments(true)
  
  // Use the parser pool for SAML processing
  val documentBuilder = parserPool.getBuilder()
  val document = documentBuilder.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_2(): Unit = {
  // Creating a BasicParserPool with explicit features including ignoreComments
  val parserPool = new BasicParserPool()
  
  // ok: scala-xml-SAMLIgnoreComments
  parserPool.setIgnoreComments(true)
  val features = new HashMap[String, Boolean]()
  features.put("http://apache.org/xml/features/disallow-doctype-decl", true)
  features.put("http://xml.org/sax/features/external-general-entities", false)
  parserPool.setBuilderFeatures(features)
  
  // Use the parser pool for SAML processing
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_3(): Unit = {
  // Initializing OpenSAML with secure parser configuration
  DefaultBootstrap.bootstrap()
  
  // Creating a BasicParserPool with secure settings
  val parserPool = new BasicParserPool()
  // ok: scala-xml-SAMLIgnoreComments
  parserPool.setIgnoreComments(true)
  parserPool.setNamespaceAware(true)
  parserPool.setCoalescing(false)
  parserPool.initialize()
  
  // Use for SAML response parsing
  val samlResponse = "<saml:Response><!-- Comment --></saml:Response>"
  val inputStream = new ByteArrayInputStream(samlResponse.getBytes())
  val document = parserPool.parse(inputStream)
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_4(): Unit = {
  // Creating a StaticBasicParserPool with secure settings
  val parserPool = new StaticBasicParserPool()
  
  // ok: scala-xml-SAMLIgnoreComments
  parserPool.setIgnoreComments(true)
  val features = new HashMap[String, Boolean]()
  features.put("http://apache.org/xml/features/disallow-doctype-decl", true)
  features.put("http://xml.org/sax/features/external-general-entities", false)
  features.put("http://xml.org/sax/features/external-parameter-entities", false)
  parserPool.setBuilderFeatures(features)
  
  // Initialize and use for SAML
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_5(): Unit = {
  // Configure parser pool with comprehensive security settings
  val parserPool = new BasicParserPool()
  
  // ok: scala-xml-SAMLIgnoreComments
  parserPool.setIgnoreComments(true)
  val features = new HashMap[String, Boolean]()
  features.put("http://apache.org/xml/features/disallow-doctype-decl", true)
  features.put("http://xml.org/sax/features/external-general-entities", false)
  features.put("http://xml.org/sax/features/external-parameter-entities", false)
  parserPool.setBuilderFeatures(features)
  
  // Use for SAML
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_6(): Unit = {
  // Creating a custom SAML processor with secure BasicParserPool
  class SAMLProcessor {
    private val parserPool = new BasicParserPool()
    
    def initialize(): Unit = {
      // ok: scala-xml-SAMLIgnoreComments
      parserPool.setIgnoreComments(true)
      parserPool.setNamespaceAware(true)
      parserPool.initialize()
    }
    
    def processSAMLResponse(samlResponse: String): Document = {
      val inputStream = new ByteArrayInputStream(samlResponse.getBytes())
      parserPool.parse(inputStream)
    }
  }
  
  val processor = new SAMLProcessor()
  processor.initialize()
  processor.processSAMLResponse("<saml:Response><!-- Comment --></saml:Response>")
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_7(): Unit = {
  // Factory method creating secure parser pool for SAML
  def createSecureSAMLParserPool(): ParserPool = {
    val pool = new BasicParserPool()
    // ok: scala-xml-SAMLIgnoreComments
    pool.setIgnoreComments(true)
    pool.setNamespaceAware(true)
    pool.setExpandEntityReferences(false)
    pool.initialize()
    pool
  }
  
  val parserPool = createSecureSAMLParserPool()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_8(): Unit = {
  // SAML configuration with comprehensive security settings
  val parserPool = new BasicParserPool()
  
  // ok: scala-xml-SAMLIgnoreComments
  parserPool.setIgnoreComments(true)
  parserPool.setMaxPoolSize(100)
  parserPool.setCoalescing(true)
  parserPool.setExpandEntityReferences(false)
  parserPool.setNamespaceAware(true)
  
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_9(): Unit = {
  // SAML processor with conditional configuration that always ensures security
  val parserPool = new BasicParserPool()
  val isSecureMode = false
  
  // ok: scala-xml-SAMLIgnoreComments
  // Always set ignoreComments to true regardless of mode
  parserPool.setIgnoreComments(true)
  
  if (isSecureMode) {
    // Additional security settings for secure mode
    val features = new HashMap[String, Boolean]()
    features.put("http://apache.org/xml/features/disallow-doctype-decl", true)
    parserPool.setBuilderFeatures(features)
  }
  
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_10(): Unit = {
  // SAML configuration with dynamic settings that enforce security
  def configureSAMLParser(additionalSecurity: Boolean): ParserPool = {
    val parserPool = new BasicParserPool()
    // ok: scala-xml-SAMLIgnoreComments
    // Always set ignoreComments to true
    parserPool.setIgnoreComments(true)
    
    if (additionalSecurity) {
      // Additional security settings
      val features = new HashMap[String, Boolean]()
      features.put("http://apache.org/xml/features/disallow-doctype-decl", true)
      parserPool.setBuilderFeatures(features)
    }
    
    parserPool.initialize()
    parserPool
  }
  
  val parserPool = configureSAMLParser(false)
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_11(): Unit = {
  // SAML processor with environment-based configuration that ensures security
  val parserPool = new BasicParserPool()
  val env = "development"
  
  // ok: scala-xml-SAMLIgnoreComments
  // Always set ignoreComments to true regardless of environment
  parserPool.setIgnoreComments(true)
  
  // Environment-specific additional settings
  if (env == "production") {
    val features = new HashMap[String, Boolean]()
    features.put("http://apache.org/xml/features/disallow-doctype-decl", true)
    parserPool.setBuilderFeatures(features)
  }
  
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_12(): Unit = {
  // SAML configuration with builder pattern ensuring security
  class SecureSAMLParserBuilder {
    private val parserPool = new BasicParserPool()
    
    // ok: scala-xml-SAMLIgnoreComments
    // Always set ignoreComments to true in constructor
    {
      parserPool.setIgnoreComments(true)
    }
    
    def withNamespaceAware(value: Boolean): SecureSAMLParserBuilder = {
      parserPool.setNamespaceAware(value)
      this
    }
    
    def withCoalescing(value: Boolean): SecureSAMLParserBuilder = {
      parserPool.setCoalescing(value)
      this
    }
    
    def build(): ParserPool = {
      parserPool.initialize()
      parserPool
    }
  }
  
  val parserPool = new SecureSAMLParserBuilder()
    .withNamespaceAware(true)
    .withCoalescing(false)
    .build()
    
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_13(): Unit = {
  // SAML configuration with feature map including security settings
  val parserPool = new BasicParserPool()
  
  // ok: scala-xml-SAMLIgnoreComments
  parserPool.setIgnoreComments(true)
  
  val features = Map(
    "http://apache.org/xml/features/disallow-doctype-decl" -> true,
    "http://xml.org/sax/features/external-general-entities" -> false,
    "http://xml.org/sax/features/external-parameter-entities" -> false
  )
  
  val javaFeatures = new HashMap[String, Boolean]()
  features.foreach { case (key, value) => javaFeatures.put(key, value) }
  parserPool.setBuilderFeatures(javaFeatures)
  
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_14(): Unit = {
  // SAML configuration with explicit setting of multiple properties including security
  val parserPool = new BasicParserPool()
  
  // ok: scala-xml-SAMLIgnoreComments
  parserPool.setIgnoreComments(true)
  parserPool.setNamespaceAware(true)
  parserPool.setCoalescing(false)
  parserPool.setExpandEntityReferences(false)
  
  parserPool.initialize()
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

def good_case_15(): Unit = {
  // SAML configuration with secure configuration object
  class SecureSAMLConfig {
    val namespaceAware: Boolean = true
    // ok: scala-xml-SAMLIgnoreComments
    val ignoreComments: Boolean = true
    val expandEntityReferences: Boolean = false
  }
  
  def configureSAMLParser(config: SecureSAMLConfig): ParserPool = {
    val parserPool = new BasicParserPool()
    parserPool.setNamespaceAware(config.namespaceAware)
    parserPool.setIgnoreComments(config.ignoreComments)
    parserPool.setExpandEntityReferences(config.expandEntityReferences)
    parserPool.initialize()
    parserPool
  }
  
  val config = new SecureSAMLConfig()
  val parserPool = configureSAMLParser(config)
  val document = parserPool.parse(new ByteArrayInputStream("<saml:Response><!-- Comment --></saml:Response>".getBytes()))
}
// {/fact}