// File: DocumentBuilderDTDEnabledTest.scala

import javax.xml.parsers.{DocumentBuilder, DocumentBuilderFactory, SAXParser, SAXParserFactory}
import org.xml.sax.{InputSource, SAXException, XMLReader}
import org.xml.sax.helpers.XMLReaderFactory
import java.io.{ByteArrayInputStream, File, FileInputStream, StringReader}
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import scala.io.Source
import org.apache.http.client.methods.HttpPost
import org.apache.http.impl.client.HttpClients
import org.apache.http.entity.StringEntity
import org.apache.http.util.EntityUtils
import org.springframework.web.bind.annotation.{RequestMapping, RequestParam, RestController}
import org.springframework.stereotype.Controller
import org.springframework.http.ResponseEntity
import play.api.mvc.{Action, AnyContent, BaseController, ControllerComponents, Request}
import play.api.libs.json.Json

object DocumentBuilderDTDEnabledTest {

  // True Positive Examples (Vulnerable Code)

  def bad_case_1(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("xml")
    val factory = DocumentBuilderFactory.newInstance()
    // ruleid: scala-documentbuilder-dtd-enabled
    val builder = factory.newDocumentBuilder()
    val inputSource = new InputSource(new StringReader(xmlContent))
    val doc = builder.parse(inputSource)
    println(doc.getDocumentElement.getNodeName)
  }

  def bad_case_2(request: HttpServletRequest): Unit = {
    val xmlContent = request.getHeader("X-XML-Data")
    val factory = DocumentBuilderFactory.newInstance()
    factory.setValidating(true)
    // ruleid: scala-documentbuilder-dtd-enabled
    val builder = factory.newDocumentBuilder()
    val inputSource = new InputSource(new StringReader(xmlContent))
    val doc = builder.parse(inputSource)
    println(doc.getDocumentElement.getTextContent)
  }

  def bad_case_3(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("data")
    val factory = DocumentBuilderFactory.newInstance()
    factory.setNamespaceAware(true)
    // ruleid: scala-documentbuilder-dtd-enabled
    val builder = factory.newDocumentBuilder()
    val bytes = xmlContent.getBytes("UTF-8")
    val doc = builder.parse(new ByteArrayInputStream(bytes))
    println(doc.getElementsByTagName("user").item(0).getTextContent)
  }

  @RestController
  class XmlController {
    @RequestMapping(Array("/process-xml"))
    def bad_case_4(@RequestParam("xml") xmlContent: String): String = {
      val factory = DocumentBuilderFactory.newInstance()
      // ruleid: scala-documentbuilder-dtd-enabled
      val builder = factory.newDocumentBuilder()
      val inputSource = new InputSource(new StringReader(xmlContent))
      val doc = builder.parse(inputSource)
      doc.getDocumentElement.getNodeName
    }
  }

  def bad_case_5(): Unit = {
    val httpClient = HttpClients.createDefault()
    val httpPost = new HttpPost("http://example.com/api")
    val response = httpClient.execute(httpPost)
    val xmlContent = EntityUtils.toString(response.getEntity)
    
    val factory = DocumentBuilderFactory.newInstance()
    // ruleid: scala-documentbuilder-dtd-enabled
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new InputSource(new StringReader(xmlContent)))
    println(doc.getDocumentElement.getNodeName)
  }

  def bad_case_6(request: HttpServletRequest): Unit = {
    val xmlFile = request.getParameter("file")
    val factory = DocumentBuilderFactory.newInstance()
    // ruleid: scala-documentbuilder-dtd-enabled
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new File(xmlFile))
    println(doc.getDocumentElement.getNodeName)
  }

  def bad_case_7(request: HttpServletRequest): Unit = {
    val xmlContent = request.getReader.lines().reduce("", (a, b) => a + b)
    try {
      val factory = DocumentBuilderFactory.newInstance()
      // ruleid: scala-documentbuilder-dtd-enabled
      val builder = factory.newDocumentBuilder()
      val inputSource = new InputSource(new StringReader(xmlContent))
      val doc = builder.parse(inputSource)
      println(doc.getElementsByTagName("root").item(0).getTextContent)
    } catch {
      case e: Exception => e.printStackTrace()
    }
  }

  def bad_case_8(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("xml")
    val saxParserFactory = SAXParserFactory.newInstance()
    // ruleid: scala-documentbuilder-dtd-enabled
    val saxParser = saxParserFactory.newSAXParser()
    val handler = new org.xml.sax.helpers.DefaultHandler()
    saxParser.parse(new InputSource(new StringReader(xmlContent)), handler)
  }

  def bad_case_9(): Unit = {
    val httpClient = HttpClients.createDefault()
    val httpPost = new HttpPost("http://example.com/api")
    val response = httpClient.execute(httpPost)
    val xmlContent = EntityUtils.toString(response.getEntity)
    
    // ruleid: scala-documentbuilder-dtd-enabled
    val xmlReader = XMLReaderFactory.createXMLReader()
    val handler = new org.xml.sax.helpers.DefaultHandler()
    xmlReader.setContentHandler(handler)
    xmlReader.parse(new InputSource(new StringReader(xmlContent)))
  }

  @Controller
  class XmlProcessingController {
    @RequestMapping(Array("/upload-xml"))
    def bad_case_10(request: HttpServletRequest): String = {
      val xmlContent = request.getParameter("xml")
      val factory = DocumentBuilderFactory.newInstance()
      factory.setCoalescing(true)
      // ruleid: scala-documentbuilder-dtd-enabled
      val builder = factory.newDocumentBuilder()
      val doc = builder.parse(new InputSource(new StringReader(xmlContent)))
      doc.getDocumentElement.getNodeName
    }
  }

  class PlayController(cc: ControllerComponents) extends BaseController {
    def bad_case_11(): Action[AnyContent] = Action { request =>
      val xmlContent = request.body.asText.getOrElse("")
      val factory = DocumentBuilderFactory.newInstance()
      // ruleid: scala-documentbuilder-dtd-enabled
      val builder = factory.newDocumentBuilder()
      val doc = builder.parse(new InputSource(new StringReader(xmlContent)))
      Ok(doc.getDocumentElement.getNodeName)
    }
  }

  def bad_case_12(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("xml")
    val factory = DocumentBuilderFactory.newInstance()
    factory.setIgnoringElementContentWhitespace(true)
    // ruleid: scala-documentbuilder-dtd-enabled
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new InputSource(new StringReader(xmlContent)))
    println(doc.getDocumentElement.getNodeName)
  }

  def bad_case_13(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("xml")
    val factory = DocumentBuilderFactory.newInstance()
    // Incomplete attempt to secure - missing important features
    factory.setValidating(false)
    // ruleid: scala-documentbuilder-dtd-enabled
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new InputSource(new StringReader(xmlContent)))
    println(doc.getDocumentElement.getNodeName)
  }

  def bad_case_14(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("xml")
    val saxParserFactory = SAXParserFactory.newInstance()
    saxParserFactory.setValidating(false)
    // ruleid: scala-documentbuilder-dtd-enabled
    val saxParser = saxParserFactory.newSAXParser()
    val handler = new org.xml.sax.helpers.DefaultHandler()
    saxParser.parse(new InputSource(new StringReader(xmlContent)), handler)
  }

  def bad_case_15(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("xml")
    val factory = DocumentBuilderFactory.newInstance()
    // Incomplete security - only setting one feature
    try {
      factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
      // ruleid: scala-documentbuilder-dtd-enabled
      val builder = factory.newDocumentBuilder()
      val doc = builder.parse(new InputSource(new StringReader(xmlContent)))
      println(doc.getDocumentElement.getNodeName)
    } catch {
      case e: Exception => e.printStackTrace()
    }
  }

  // True Negative Examples (Secure Code)

  def good_case_1(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("xml")
    val factory = DocumentBuilderFactory.newInstance()
    // ok: scala-documentbuilder-dtd-enabled
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
    factory.setXIncludeAware(false)
    factory.setExpandEntityReferences(false)
    val builder = factory.newDocumentBuilder()
    val inputSource = new InputSource(new StringReader(xmlContent))
    val doc = builder.parse(inputSource)
    println(doc.getDocumentElement.getNodeName)
  }

  def good_case_2(request: HttpServletRequest): Unit = {
    val xmlContent = request.getHeader("X-XML-Data")
    val factory = DocumentBuilderFactory.newInstance()
    // ok: scala-documentbuilder-dtd-enabled
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    val builder = factory.newDocumentBuilder()
    val inputSource = new InputSource(new StringReader(xmlContent))
    val doc = builder.parse(inputSource)
    println(doc.getDocumentElement.getTextContent)
  }

  def good_case_3(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("data")
    val factory = DocumentBuilderFactory.newInstance()
    factory.setNamespaceAware(true)
    // ok: scala-documentbuilder-dtd-enabled
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
    val builder = factory.newDocumentBuilder()
    val bytes = xmlContent.getBytes("UTF-8")
    val doc = builder.parse(new ByteArrayInputStream(bytes))
    println(doc.getElementsByTagName("user").item(0).getTextContent)
  }

  @RestController
  class SecureXmlController {
    @RequestMapping(Array("/process-xml-secure"))
    def good_case_4(@RequestParam("xml") xmlContent: String): String = {
      val factory = DocumentBuilderFactory.newInstance()
      // ok: scala-documentbuilder-dtd-enabled
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
      factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
      val builder = factory.newDocumentBuilder()
      val inputSource = new InputSource(new StringReader(xmlContent))
      val doc = builder.parse(inputSource)
      doc.getDocumentElement.getNodeName
    }
  }

  def good_case_5(): Unit = {
    val httpClient = HttpClients.createDefault()
    val httpPost = new HttpPost("http://example.com/api")
    val response = httpClient.execute(httpPost)
    val xmlContent = EntityUtils.toString(response.getEntity)
    
    val factory = DocumentBuilderFactory.newInstance()
    // ok: scala-documentbuilder-dtd-enabled
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    factory.setExpandEntityReferences(false)
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new InputSource(new StringReader(xmlContent)))
    println(doc.getDocumentElement.getNodeName)
  }

  def good_case_6(request: HttpServletRequest): Unit = {
    val xmlFile = request.getParameter("file")
    val factory = DocumentBuilderFactory.newInstance()
    // ok: scala-documentbuilder-dtd-enabled
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new File(xmlFile))
    println(doc.getDocumentElement.getNodeName)
  }

  def good_case_7(request: HttpServletRequest): Unit = {
    val xmlContent = request.getReader.lines().reduce("", (a, b) => a + b)
    try {
      val factory = DocumentBuilderFactory.newInstance()
      // ok: scala-documentbuilder-dtd-enabled
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
      factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
      factory.setXIncludeAware(false)
      val builder = factory.newDocumentBuilder()
      val inputSource = new InputSource(new StringReader(xmlContent))
      val doc = builder.parse(inputSource)
      println(doc.getElementsByTagName("root").item(0).getTextContent)
    } catch {
      case e: Exception => e.printStackTrace()
    }
  }

  def good_case_8(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("xml")
    val saxParserFactory = SAXParserFactory.newInstance()
    // ok: scala-documentbuilder-dtd-enabled
    saxParserFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    saxParserFactory.setFeature("http://xml.org/sax/features/external-general-entities", false)
    saxParserFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    val saxParser = saxParserFactory.newSAXParser()
    val handler = new org.xml.sax.helpers.DefaultHandler()
    saxParser.parse(new InputSource(new StringReader(xmlContent)), handler)
  }

  def good_case_9(): Unit = {
    val httpClient = HttpClients.createDefault()
    val httpPost = new HttpPost("http://example.com/api")
    val response = httpClient.execute(httpPost)
    val xmlContent = EntityUtils.toString(response.getEntity)
    
    val xmlReader = XMLReaderFactory.createXMLReader()
    // ok: scala-documentbuilder-dtd-enabled
    xmlReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", false)
    xmlReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    val handler = new org.xml.sax.helpers.DefaultHandler()
    xmlReader.setContentHandler(handler)
    xmlReader.parse(new InputSource(new StringReader(xmlContent)))
  }

  @Controller
  class SecureXmlProcessingController {
    @RequestMapping(Array("/upload-xml-secure"))
    def good_case_10(request: HttpServletRequest): String = {
      val xmlContent = request.getParameter("xml")
      val factory = DocumentBuilderFactory.newInstance()
      factory.setCoalescing(true)
      // ok: scala-documentbuilder-dtd-enabled
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
      factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
      val builder = factory.newDocumentBuilder()
      val doc = builder.parse(new InputSource(new StringReader(xmlContent)))
      doc.getDocumentElement.getNodeName
    }
  }

  class SecurePlayController(cc: ControllerComponents) extends BaseController {
    def good_case_11(): Action[AnyContent] = Action { request =>
      val xmlContent = request.body.asText.getOrElse("")
      val factory = DocumentBuilderFactory.newInstance()
      // ok: scala-documentbuilder-dtd-enabled
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
      factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
      val builder = factory.newDocumentBuilder()
      val doc = builder.parse(new InputSource(new StringReader(xmlContent)))
      Ok(doc.getDocumentElement.getNodeName)
    }
  }

  def good_case_12(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("xml")
    val factory = DocumentBuilderFactory.newInstance()
    factory.setIgnoringElementContentWhitespace(true)
    // ok: scala-documentbuilder-dtd-enabled
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    factory.setExpandEntityReferences(false)
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new InputSource(new StringReader(xmlContent)))
    println(doc.getDocumentElement.getNodeName)
  }

  def good_case_13(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("xml")
    val factory = DocumentBuilderFactory.newInstance()
    factory.setValidating(false)
    // ok: scala-documentbuilder-dtd-enabled
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    factory.setXIncludeAware(false)
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new InputSource(new StringReader(xmlContent)))
    println(doc.getDocumentElement.getNodeName)
  }

  def good_case_14(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("xml")
    val saxParserFactory = SAXParserFactory.newInstance()
    saxParserFactory.setValidating(false)
    // ok: scala-documentbuilder-dtd-enabled
    saxParserFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    saxParserFactory.setFeature("http://xml.org/sax/features/external-general-entities", false)
    val saxParser = saxParserFactory.newSAXParser()
    val handler = new org.xml.sax.helpers.DefaultHandler()
    saxParser.parse(new InputSource(new StringReader(xmlContent)), handler)
  }

  def good_case_15(request: HttpServletRequest): Unit = {
    val xmlContent = request.getParameter("xml")
    val factory = DocumentBuilderFactory.newInstance()
    try {
      // ok: scala-documentbuilder-dtd-enabled
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
      factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
      factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
      val builder = factory.newDocumentBuilder()
      val doc = builder.parse(new InputSource(new StringReader(xmlContent)))
      println(doc.getDocumentElement.getNodeName)
    } catch {
      case e: Exception => e.printStackTrace()
    }
  }
}