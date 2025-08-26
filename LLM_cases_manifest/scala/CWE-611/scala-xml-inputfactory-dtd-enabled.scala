// File: XMLInputFactorySecurityTests.scala

import javax.xml.stream.{XMLInputFactory, XMLStreamReader}
import java.io.{ByteArrayInputStream, FileInputStream, StringReader}
import scala.xml.{XML, Node}
import javax.xml.transform.stream.StreamSource
import javax.xml.transform.{Source => XMLSource}
import scala.io.Source
import play.api.mvc._
import play.api.http._
import play.api.libs.json._
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.{HttpRequest, HttpResponse}
import akka.http.scaladsl.unmarshalling.Unmarshal
import akka.http.scaladsl.model.HttpEntity

object XMLInputFactorySecurityTests {

  // True Positive Examples (Vulnerable Code)

  def bad_case_1(): Unit = {
    // Creating XMLInputFactory with default settings (DTD enabled)
    val factory = XMLInputFactory.newInstance()
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val xmlReader = factory.createXMLStreamReader(new FileInputStream("input.xml"))
    // Process XML
    while(xmlReader.hasNext) {
      xmlReader.next()
    }
  }

  def bad_case_2(request: play.api.mvc.Request[AnyContent]): Unit = {
    val xmlString = request.body.asText.getOrElse("")
    val factory = XMLInputFactory.newInstance()
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val xmlReader = factory.createXMLStreamReader(new StringReader(xmlString))
    // Process XML from user input
    while(xmlReader.hasNext) {
      xmlReader.next()
    }
  }

  def bad_case_3(): Unit = {
    val factory = XMLInputFactory.newInstance()
    // Explicitly enabling DTD support
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, true)
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val xmlReader = factory.createXMLStreamReader(new FileInputStream("config.xml"))
    processXml(xmlReader)
  }

  def bad_case_4(httpRequest: HttpRequest): Unit = {
    val xmlContent = httpRequest.entity.toString
    val factory = XMLInputFactory.newInstance()
    // Setting external entities to true explicitly
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true)
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val xmlReader = factory.createXMLStreamReader(new StringReader(xmlContent))
    // Process XML
    while(xmlReader.hasNext) {
      xmlReader.next()
    }
  }

  def bad_case_5(): Unit = {
    val factory = XMLInputFactory.newInstance()
    // Setting both properties to true explicitly
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, true)
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true)
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new FileInputStream("data.xml"))
    processXml(reader)
  }

  def bad_case_6(request: play.api.mvc.Request[AnyContent]): Unit = {
    val xmlData = request.body.asXml.getOrElse(<empty/>).toString()
    val factory = XMLInputFactory.newInstance()
    // Only disabling coalescing, but leaving DTD enabled
    factory.setProperty(XMLInputFactory.IS_COALESCING, false)
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new StringReader(xmlData))
    processXml(reader)
  }

  def bad_case_7(): Unit = {
    val xmlContent = Source.fromFile("user_data.xml").mkString
    val factory = XMLInputFactory.newInstance()
    // Setting irrelevant property but leaving DTD enabled
    factory.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, true)
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new StringReader(xmlContent))
    processXml(reader)
  }

  def bad_case_8(request: play.api.mvc.Request[AnyContent]): Unit = {
    val xmlString = request.body.asText.getOrElse("")
    val factory = XMLInputFactory.newFactory() // Alternative factory creation method
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new ByteArrayInputStream(xmlString.getBytes("UTF-8")))
    processXml(reader)
  }

  def bad_case_9(): Unit = {
    val factory = XMLInputFactory.newInstance()
    // Disabling external entities but leaving DTD enabled
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new FileInputStream("config.xml"))
    processXml(reader)
  }

  def bad_case_10(httpRequest: HttpRequest): Unit = {
    val xmlContent = httpRequest.entity.toString
    val factory = XMLInputFactory.newInstance()
    // Setting DTD support to true explicitly
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.box(true))
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new StringReader(xmlContent))
    processXml(reader)
  }

  def bad_case_11(): Unit = {
    val xmlSource = new StreamSource(new FileInputStream("data.xml"))
    val factory = XMLInputFactory.newInstance()
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(xmlSource)
    processXml(reader)
  }

  def bad_case_12(request: play.api.mvc.Request[AnyContent]): Unit = {
    val xmlString = request.body.asText.getOrElse("")
    val factory = XMLInputFactory.newInstance()
    // Setting property with string name instead of constant
    factory.setProperty("javax.xml.stream.supportDTD", true)
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new StringReader(xmlString))
    processXml(reader)
  }

  def bad_case_13(): Unit = {
    val factory = XMLInputFactory.newInstance()
    // Enabling DTD with variable
    val enableDTD = true
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, enableDTD)
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new FileInputStream("input.xml"))
    processXml(reader)
  }

  def bad_case_14(request: play.api.mvc.Request[AnyContent]): Unit = {
    val xmlString = request.body.asText.getOrElse("")
    // Creating factory in a different way
    val factory = javax.xml.stream.XMLInputFactory.newFactory()
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLEventReader(new StringReader(xmlString))
    while(reader.hasNext) {
      reader.nextEvent()
    }
  }

  def bad_case_15(): Unit = {
    val xmlContent = Source.fromFile("data.xml").mkString
    val factory = XMLInputFactory.newInstance()
    // Setting external entities to false but DTD still enabled
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    factory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false)
    // ruleid: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new StringReader(xmlContent))
    processXml(reader)
  }

  // True Negative Examples (Secure Code)

  def good_case_1(): Unit = {
    val factory = XMLInputFactory.newInstance()
    // Disabling DTD support
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    // ok: scala-xml-inputfactory-dtd-enabled
    val xmlReader = factory.createXMLStreamReader(new FileInputStream("input.xml"))
    // Process XML
    while(xmlReader.hasNext) {
      xmlReader.next()
    }
  }

  def good_case_2(request: play.api.mvc.Request[AnyContent]): Unit = {
    val xmlString = request.body.asText.getOrElse("")
    val factory = XMLInputFactory.newInstance()
    // Disabling external entities
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    // ok: scala-xml-inputfactory-dtd-enabled
    val xmlReader = factory.createXMLStreamReader(new StringReader(xmlString))
    // Process XML from user input
    while(xmlReader.hasNext) {
      xmlReader.next()
    }
  }

  def good_case_3(): Unit = {
    val factory = XMLInputFactory.newInstance()
    // Disabling DTD and external entities
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    // ok: scala-xml-inputfactory-dtd-enabled
    val xmlReader = factory.createXMLStreamReader(new FileInputStream("config.xml"))
    processXml(xmlReader)
  }

  def good_case_4(httpRequest: HttpRequest): Unit = {
    val xmlContent = httpRequest.entity.toString
    val factory = XMLInputFactory.newInstance()
    // Disabling DTD support with Boolean object
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE)
    // ok: scala-xml-inputfactory-dtd-enabled
    val xmlReader = factory.createXMLStreamReader(new StringReader(xmlContent))
    // Process XML
    while(xmlReader.hasNext) {
      xmlReader.next()
    }
  }

  def good_case_5(): Unit = {
    val factory = XMLInputFactory.newInstance()
    // Disabling DTD and external entities with Boolean objects
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE)
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE)
    // ok: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new FileInputStream("data.xml"))
    processXml(reader)
  }

  def good_case_6(request: play.api.mvc.Request[AnyContent]): Unit = {
    val xmlData = request.body.asXml.getOrElse(<empty/>).toString()
    val factory = XMLInputFactory.newInstance()
    // Disabling DTD and setting other properties
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    factory.setProperty(XMLInputFactory.IS_COALESCING, true)
    // ok: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new StringReader(xmlData))
    processXml(reader)
  }

  def good_case_7(): Unit = {
    val xmlContent = Source.fromFile("user_data.xml").mkString
    val factory = XMLInputFactory.newInstance()
    // Disabling DTD and setting namespace awareness
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    factory.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, true)
    // ok: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new StringReader(xmlContent))
    processXml(reader)
  }

  def good_case_8(request: play.api.mvc.Request[AnyContent]): Unit = {
    val xmlString = request.body.asText.getOrElse("")
    val factory = XMLInputFactory.newFactory() // Alternative factory creation method
    // Disabling DTD and external entities
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    // ok: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new ByteArrayInputStream(xmlString.getBytes("UTF-8")))
    processXml(reader)
  }

  def good_case_9(): Unit = {
    val factory = XMLInputFactory.newInstance()
    // Disabling both DTD and external entities
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    // Additional security measure
    factory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false)
    // ok: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new FileInputStream("config.xml"))
    processXml(reader)
  }

  def good_case_10(httpRequest: HttpRequest): Unit = {
    val xmlContent = httpRequest.entity.toString
    val factory = XMLInputFactory.newInstance()
    // Setting DTD support to false with string property name
    factory.setProperty("javax.xml.stream.supportDTD", false)
    factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false)
    // ok: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new StringReader(xmlContent))
    processXml(reader)
  }

  def good_case_11(): Unit = {
    val xmlSource = new StreamSource(new FileInputStream("data.xml"))
    val factory = XMLInputFactory.newInstance()
    // Disabling DTD and external entities
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    // ok: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(xmlSource)
    processXml(reader)
  }

  def good_case_12(request: play.api.mvc.Request[AnyContent]): Unit = {
    val xmlString = request.body.asText.getOrElse("")
    val factory = XMLInputFactory.newInstance()
    // Using variables to set security properties
    val dtdEnabled = false
    val externalEntitiesEnabled = false
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, dtdEnabled)
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, externalEntitiesEnabled)
    // ok: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new StringReader(xmlString))
    processXml(reader)
  }

  def good_case_13(): Unit = {
    // Creating a secure factory with helper method
    val factory = createSecureXMLInputFactory()
    // ok: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new FileInputStream("input.xml"))
    processXml(reader)
  }

  def good_case_14(request: play.api.mvc.Request[AnyContent]): Unit = {
    val xmlString = request.body.asText.getOrElse("")
    val factory = javax.xml.stream.XMLInputFactory.newFactory()
    // Disabling DTD for XMLEventReader
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    // ok: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLEventReader(new StringReader(xmlString))
    while(reader.hasNext) {
      reader.nextEvent()
    }
  }

  def good_case_15(): Unit = {
    val xmlContent = Source.fromFile("data.xml").mkString
    // Creating a factory with all security features disabled
    val factory = XMLInputFactory.newInstance()
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    factory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false)
    // ok: scala-xml-inputfactory-dtd-enabled
    val reader = factory.createXMLStreamReader(new StringReader(xmlContent))
    processXml(reader)
  }

  // Helper methods
  private def processXml(reader: XMLStreamReader): Unit = {
    while(reader.hasNext) {
      reader.next()
      // Process XML content
    }
  }

  private def createSecureXMLInputFactory(): XMLInputFactory = {
    val factory = XMLInputFactory.newInstance()
    // Disable DTD and external entities
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    factory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false)
    factory
  }
}