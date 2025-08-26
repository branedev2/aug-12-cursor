import javax.xml.transform.TransformerFactory
import javax.xml.transform.stream.StreamSource
import javax.xml.transform.stream.StreamResult
import javax.xml.XMLConstants
import java.io.StringReader
import java.io.StringWriter
import scala.io.Source
import scala.util.Try
import play.api.mvc._
import play.api.http._
import play.api.routing._
import javax.inject._
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Document
import javax.xml.transform.dom.DOMSource
// {fact rule=xml-external-entity@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(): Unit = {
  // Creating a TransformerFactory without any security settings
  val factory = TransformerFactory.newInstance()
  // ruleid: scala-xxe-trans
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_2(): Unit = {
  val factory = TransformerFactory.newInstance()
  // Explicitly setting ACCESS_EXTERNAL_DTD to "all" (dangerous)
  // ruleid: scala-xxe-trans
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all")
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_3(): Unit = {
  val factory = TransformerFactory.newInstance()
  // Explicitly setting ACCESS_EXTERNAL_STYLESHEET to "all" (dangerous)
  // ruleid: scala-xxe-trans
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "all")
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_4(): Unit = {
  val factory = TransformerFactory.newInstance()
  // Setting both external DTD and stylesheet access to "all" (very dangerous)
  // ruleid: scala-xxe-trans
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all")
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "all")
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}

def bad_case_5(@Inject() request: Request[AnyContent]): Unit = {
  // Getting XML from HTTP request
  val xmlString = request.body.asText.getOrElse("")
  val factory = TransformerFactory.newInstance()
  // ruleid: scala-xxe-trans
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader(xmlString))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}

def bad_case_6(@Inject() request: Request[AnyContent]): Unit = {
  // Processing XML from HTTP request with insecure settings
  val xmlString = request.body.asText.getOrElse("")
  val factory = TransformerFactory.newInstance()
  // ruleid: scala-xxe-trans
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "file,http")
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader(xmlString))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_7(): Unit = {
  // Using a variable to store the dangerous setting
  val factory = TransformerFactory.newInstance()
  val accessValue = "all"
  // ruleid: scala-xxe-trans
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, accessValue)
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_8(): Unit = {
  // Using conditional to set insecure configuration
  val factory = TransformerFactory.newInstance()
  val enableExternalAccess = true
  
  if (enableExternalAccess) {
    // ruleid: scala-xxe-trans
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "all")
  }
  
  val transformer = factory.newTransformer()
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}

def bad_case_9(@Inject() request: Request[AnyContent]): Unit = {
  // Using a custom function to create the factory with insecure settings
  def createFactory(): TransformerFactory = {
    val factory = TransformerFactory.newInstance()
    // ruleid: scala-xxe-trans
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all")
    factory
  }
  
  val xmlString = request.body.asText.getOrElse("")
  val factory = createFactory()
  val transformer = factory.newTransformer()
  val xmlInput = new StreamSource(new StringReader(xmlString))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_10(): Unit = {
  // Using a try-catch block but still with insecure settings
  val factory = TransformerFactory.newInstance()
  
  try {
    // ruleid: scala-xxe-trans
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all")
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "all")
  } catch {
    case e: Exception => println("Error setting attributes: " + e.getMessage)
  }
  
  val transformer = factory.newTransformer()
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_11(): Unit = {
  // Using a map to store and apply insecure settings
  val factory = TransformerFactory.newInstance()
  val settings = Map(
    XMLConstants.ACCESS_EXTERNAL_DTD -> "all",
    XMLConstants.ACCESS_EXTERNAL_STYLESHEET -> "all"
  )
  
  settings.foreach { case (key, value) =>
    // ruleid: scala-xxe-trans
    factory.setAttribute(key, value)
  }
  
  val transformer = factory.newTransformer()
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_12(): Unit = {
  // Setting feature secure processing to false (dangerous)
  val factory = TransformerFactory.newInstance()
  // ruleid: scala-xxe-trans
  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false)
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}

def bad_case_13(@Inject() request: Request[AnyContent]): Unit = {
  // Processing XML from file with insecure transformer
  val xmlFile = request.getQueryString("file").getOrElse("default.xml")
  val factory = TransformerFactory.newInstance()
  // ruleid: scala-xxe-trans
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new File(xmlFile))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_14(): Unit = {
  // Using DOM source but still with insecure transformer
  val dbFactory = DocumentBuilderFactory.newInstance()
  val dBuilder = dbFactory.newDocumentBuilder()
  val doc: Document = dBuilder.parse(new File("input.xml"))
  
  val factory = TransformerFactory.newInstance()
  // ruleid: scala-xxe-trans
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all")
  val transformer = factory.newTransformer()
  
  val source = new DOMSource(doc)
  val result = new StreamResult(new StringWriter())
  transformer.transform(source, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_15(): Unit = {
  // Creating multiple transformers from the same insecure factory
  val factory = TransformerFactory.newInstance()
  // ruleid: scala-xxe-trans
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "http,file")
  
  val transformer1 = factory.newTransformer()
  val transformer2 = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer1.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

// True Negative Examples (Secure Code)

def good_case_1(): Unit = {
  val factory = TransformerFactory.newInstance()
  // ok: scala-xxe-trans
  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_2(): Unit = {
  val factory = TransformerFactory.newInstance()
  // ok: scala-xxe-trans
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_3(): Unit = {
  val factory = TransformerFactory.newInstance()
  // ok: scala-xxe-trans
  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}

def good_case_4(@Inject() request: Request[AnyContent]): Unit = {
  // Processing XML from HTTP request with secure settings
  val xmlString = request.body.asText.getOrElse("")
  val factory = TransformerFactory.newInstance()
  // ok: scala-xxe-trans
  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader(xmlString))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_5(): Unit = {
  // Using a custom function to create secure factory
  def createSecureFactory(): TransformerFactory = {
    val factory = TransformerFactory.newInstance()
    // ok: scala-xxe-trans
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
    factory
  }
  
  val factory = createSecureFactory()
  val transformer = factory.newTransformer()
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_6(): Unit = {
  // Using try-catch with secure settings
  val factory = TransformerFactory.newInstance()
  
  try {
    // ok: scala-xxe-trans
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
  } catch {
    case e: Exception => println("Error setting secure attributes: " + e.getMessage)
  }
  
  val transformer = factory.newTransformer()
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_7(): Unit = {
  // Using a map to store and apply secure settings
  val factory = TransformerFactory.newInstance()
  val secureSettings = Map(
    XMLConstants.ACCESS_EXTERNAL_DTD -> "",
    XMLConstants.ACCESS_EXTERNAL_STYLESHEET -> ""
  )
  
  // ok: scala-xxe-trans
  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
  secureSettings.foreach { case (key, value) =>
    factory.setAttribute(key, value)
  }
  
  val transformer = factory.newTransformer()
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}

def good_case_8(@Inject() request: Request[AnyContent]): Unit = {
  // Processing XML from file with secure transformer
  val xmlFile = request.getQueryString("file").getOrElse("default.xml")
  val factory = TransformerFactory.newInstance()
  // ok: scala-xxe-trans
  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new File(xmlFile))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_9(): Unit = {
  // Using DOM source with secure transformer
  val dbFactory = DocumentBuilderFactory.newInstance()
  dbFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
  dbFactory.setExpandEntityReferences(false)
  val dBuilder = dbFactory.newDocumentBuilder()
  val doc: Document = dBuilder.parse(new File("input.xml"))
  
  val factory = TransformerFactory.newInstance()
  // ok: scala-xxe-trans
  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
  val transformer = factory.newTransformer()
  
  val source = new DOMSource(doc)
  val result = new StreamResult(new StringWriter())
  transformer.transform(source, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_10(): Unit = {
  // Creating multiple transformers from the same secure factory
  val factory = TransformerFactory.newInstance()
  // ok: scala-xxe-trans
  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
  
  val transformer1 = factory.newTransformer()
  val transformer2 = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer1.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_11(): Unit = {
  // Using conditional logic to ensure secure settings
  val factory = TransformerFactory.newInstance()
  val isSecure = true
  
  if (isSecure) {
    // ok: scala-xxe-trans
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
  }
  
  val transformer = factory.newTransformer()
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_12(): Unit = {
  // Using a utility function to apply secure settings
  def secureFactory(factory: TransformerFactory): Unit = {
    // ok: scala-xxe-trans
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
  }
  
  val factory = TransformerFactory.newInstance()
  secureFactory(factory)
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_13(): Unit = {
  // Using constants for secure values
  val factory = TransformerFactory.newInstance()
  val SECURE_VALUE = ""
  val SECURE_PROCESSING = true
  
  // ok: scala-xxe-trans
  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, SECURE_PROCESSING)
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, SECURE_VALUE)
  factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, SECURE_VALUE)
  
  val transformer = factory.newTransformer()
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_14(): Unit = {
  // Using a builder pattern for secure factory
  class SecureTransformerFactoryBuilder {
    private val factory = TransformerFactory.newInstance()
    
    def build(): TransformerFactory = {
      // ok: scala-xxe-trans
      factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
      factory
    }
  }
  
  val factory = new SecureTransformerFactoryBuilder().build()
  val transformer = factory.newTransformer()
  
  val xmlInput = new StreamSource(new StringReader("<root>test</root>"))
  val result = new StreamResult(new StringWriter())
  transformer.transform(xmlInput, result)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_15(): Unit = {
  // Using a wrapper class for secure transformer operations
  class SecureXmlTransformer {
    private val factory = TransformerFactory.newInstance()
    
    // ok: scala-xxe-trans
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
    
    def transform(input: String): String = {
      val transformer = factory.newTransformer()
      val xmlInput = new StreamSource(new StringReader(input))
      val writer = new StringWriter()
      val result = new StreamResult(writer)
      transformer.transform(xmlInput, result)
      writer.toString
    }
  }
  
  val secureTransformer = new SecureXmlTransformer()
  val output = secureTransformer.transform("<root>test</root>")
}
// {/fact}