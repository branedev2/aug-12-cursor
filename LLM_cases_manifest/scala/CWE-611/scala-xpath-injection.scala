import scala.xml._
import javax.xml.xpath._
import org.w3c.dom.{Document, NodeList}
import javax.xml.parsers.DocumentBuilderFactory
import java.io.{ByteArrayInputStream, StringReader}
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamSource
import play.api.mvc._
import play.api.http._
import play.api.routing._
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.{HttpRequest, HttpResponse}
import org.apache.commons.lang3.StringEscapeUtils
import scala.io.Source
// {fact rule=xml-external-entity@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(request: play.api.mvc.Request[AnyContent]): NodeList = {
  val username = request.getQueryString("username").getOrElse("")
  
  val xmlString = """
    <users>
      <user>
        <name>admin</name>
        <role>administrator</role>
      </user>
      <user>
        <name>guest</name>
        <role>guest</role>
      </user>
    </users>
  """
  
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlString.getBytes("UTF-8")))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val expression = xPath.compile(s"/users/user[name='${username}']")
  
  expression.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_2(request: play.api.mvc.Request[AnyContent]): String = {
  val userId = request.body.asFormUrlEncoded.get("userId").head
  
  val xmlData = """
    <company>
      <employee id="1"><name>John</name><position>Developer</position></employee>
      <employee id="2"><name>Jane</name><position>Manager</position></employee>
    </company>
  """
  
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val expr = xPath.compile(s"//employee[@id='" + userId + "']/name/text()")
  
  expr.evaluate(doc)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_3(): NodeList = {
  val request = play.api.mvc.Request(
    FakeHttpHeaders(Seq(("X-User-Role", Seq("admin")))),
    FakeRequestBody()
  )
  
  val role = request.headers.get("X-User-Role").getOrElse("")
  
  val xmlContent = "<roles><role name='admin'><permission>all</permission></role><role name='user'><permission>limited</permission></role></roles>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlContent.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val expression = xPath.compile("/roles/role[@name=\"" + role + "\"]/permission")
  
  expression.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_4(request: akka.http.scaladsl.model.HttpRequest): NodeList = {
  val query = request.uri.query().get("search").getOrElse("")
  
  val xmlData = "<books><book><title>Scala Programming</title><author>Martin Odersky</author></book></books>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val expr = xPath.compile(s"/books/book[contains(title, '$query')]")
  
  expr.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_5(request: play.api.mvc.Request[AnyContent]): String = {
  val category = request.cookies.get("category").map(_.value).getOrElse("")
  
  val xmlData = "<products><category name='electronics'><item>Phone</item></category><category name='books'><item>Scala Guide</item></category></products>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val result = xPath.evaluate("/products/category[@name='" + category + "']/item/text()", doc)
  
  result
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_6(request: play.api.mvc.Request[AnyContent]): NodeList = {
  val department = request.body.asJson.get("department").as[String]
  
  val xmlContent = "<organization><department name='IT'><employee>John</employee></department><department name='HR'><employee>Jane</employee></department></organization>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlContent.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val expression = xPath.compile("/organization/department[@name=\"" + department + "\"]/employee")
  
  expression.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_7(request: play.api.mvc.Request[AnyContent]): String = {
  val productId = request.getQueryString("productId").getOrElse("")
  
  val xmlData = "<inventory><product id='1'><price>100</price></product><product id='2'><price>200</price></product></inventory>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val price = xPath.evaluate("/inventory/product[@id=" + productId + "]/price/text()", doc)
  
  price
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_8(request: akka.http.scaladsl.model.HttpRequest): NodeList = {
  val tag = request.uri.query().get("tag").getOrElse("")
  
  val xmlData = "<blog><post><tag>scala</tag><content>Scala tutorial</content></post><post><tag>java</tag><content>Java guide</content></post></blog>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val expr = xPath.compile(s"/blog/post[tag='$tag']")
  
  expr.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_9(request: play.api.mvc.Request[AnyContent]): String = {
  val attribute = request.body.asFormUrlEncoded.get("attribute").head
  val value = request.body.asFormUrlEncoded.get("value").head
  
  val xmlData = "<data><entry key='name' value='John'/><entry key='age' value='30'/></data>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val result = xPath.evaluate(s"/data/entry[@key='$attribute' and @value='$value']/@key", doc)
  
  result
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_10(request: play.api.mvc.Request[AnyContent]): NodeList = {
  val xpath = request.getQueryString("xpath").getOrElse("")
  
  val xmlData = "<config><setting name='timeout' value='30'/><setting name='retries' value='3'/></config>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val expr = xPath.compile(xpath)
  
  expr.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_11(request: play.api.mvc.Request[AnyContent]): String = {
  val elementName = request.headers.get("X-Element").getOrElse("")
  
  val xmlData = "<root><element1>Value1</element1><element2>Value2</element2></root>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val result = xPath.evaluate("/root/" + elementName + "/text()", doc)
  
  result
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_12(request: akka.http.scaladsl.model.HttpRequest): NodeList = {
  val operator = request.uri.query().get("operator").getOrElse("")
  val value = request.uri.query().get("value").getOrElse("")
  
  val xmlData = "<numbers><number value='10'/><number value='20'/><number value='30'/></numbers>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val expr = xPath.compile(s"/numbers/number[@value $operator $value]")
  
  expr.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_13(request: play.api.mvc.Request[AnyContent]): String = {
  val namespace = request.getQueryString("ns").getOrElse("")
  val element = request.getQueryString("element").getOrElse("")
  
  val xmlData = "<root xmlns:ns1='http://example.com/ns1'><ns1:elem>Value</ns1:elem></root>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val result = xPath.evaluate(s"/root/$namespace:$element/text()", doc)
  
  result
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_14(request: play.api.mvc.Request[AnyContent]): NodeList = {
  val position = request.body.asJson.get("position").as[String]
  
  val xmlData = "<team><member position='developer'>Alice</member><member position='manager'>Bob</member></team>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val expr = xPath.compile("/team/member[@position='" + position + "']")
  
  expr.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

def bad_case_15(request: play.api.mvc.Request[AnyContent]): String = {
  val condition = request.getQueryString("condition").getOrElse("")
  
  val xmlData = "<data><item type='A' value='1'/><item type='B' value='2'/></data>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ruleid: scala-xpath-injection
  val result = xPath.evaluate(s"/data/item[${condition}]/@value", doc)
  
  result
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

// True Negatives (Safe Code)

def good_case_1(request: play.api.mvc.Request[AnyContent]): NodeList = {
  val username = request.getQueryString("username").getOrElse("")
  
  // Sanitize the input by escaping special characters
  val sanitizedUsername = StringEscapeUtils.escapeXml11(username)
  
  val xmlString = """
    <users>
      <user>
        <name>admin</name>
        <role>administrator</role>
      </user>
      <user>
        <name>guest</name>
        <role>guest</role>
      </user>
    </users>
  """
  
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlString.getBytes("UTF-8")))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ok: scala-xpath-injection
  val expression = xPath.compile(s"/users/user[name='${sanitizedUsername}']")
  
  expression.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_2(request: play.api.mvc.Request[AnyContent]): String = {
  val userId = request.body.asFormUrlEncoded.get("userId").head
  
  // Validate that userId is numeric
  if (!userId.matches("\\d+")) {
    throw new IllegalArgumentException("Invalid user ID")
  }
  
  val xmlData = """
    <company>
      <employee id="1"><name>John</name><position>Developer</position></employee>
      <employee id="2"><name>Jane</name><position>Manager</position></employee>
    </company>
  """
  
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ok: scala-xpath-injection
  val expr = xPath.compile(s"//employee[@id='" + userId + "']/name/text()")
  
  expr.evaluate(doc)
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_3(): NodeList = {
  val request = play.api.mvc.Request(
    FakeHttpHeaders(Seq(("X-User-Role", Seq("admin")))),
    FakeRequestBody()
  )
  
  val role = request.headers.get("X-User-Role").getOrElse("")
  
  // Whitelist validation
  val validRoles = Set("admin", "user", "guest")
  if (!validRoles.contains(role)) {
    throw new IllegalArgumentException("Invalid role")
  }
  
  val xmlContent = "<roles><role name='admin'><permission>all</permission></role><role name='user'><permission>limited</permission></role></roles>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlContent.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ok: scala-xpath-injection
  val expression = xPath.compile("/roles/role[@name=\"" + role + "\"]/permission")
  
  expression.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_4(request: akka.http.scaladsl.model.HttpRequest): NodeList = {
  val query = request.uri.query().get("search").getOrElse("")
  
  // Sanitize the input
  val sanitizedQuery = StringEscapeUtils.escapeXml11(query)
  
  val xmlData = "<books><book><title>Scala Programming</title><author>Martin Odersky</author></book></books>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ok: scala-xpath-injection
  val expr = xPath.compile(s"/books/book[contains(title, '$sanitizedQuery')]")
  
  expr.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_5(request: play.api.mvc.Request[AnyContent]): String = {
  val category = request.cookies.get("category").map(_.value).getOrElse("")
  
  // Use parameterized XPath with variables
  val xmlData = "<products><category name='electronics'><item>Phone</item></category><category name='books'><item>Scala Guide</item></category></products>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  val expr = xPath.compile("/products/category[@name=$cat]/item/text()")
  
  // Create variable bindings
  val variables = new XPathVariableResolver {
    override def resolveVariable(variableName: javax.xml.namespace.QName): AnyRef = {
      if (variableName.getLocalPart == "cat") category else null
    }
  }
  
  xPath.setXPathVariableResolver(variables)
  // ok: scala-xpath-injection
  val result = expr.evaluate(doc)
  
  result
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_6(request: play.api.mvc.Request[AnyContent]): NodeList = {
  val department = request.body.asJson.get("department").as[String]
  
  // Sanitize input
  val sanitizedDept = StringEscapeUtils.escapeXml11(department)
  
  val xmlContent = "<organization><department name='IT'><employee>John</employee></department><department name='HR'><employee>Jane</employee></department></organization>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlContent.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ok: scala-xpath-injection
  val expression = xPath.compile("/organization/department[@name=\"" + sanitizedDept + "\"]/employee")
  
  expression.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_7(request: play.api.mvc.Request[AnyContent]): String = {
  val productId = request.getQueryString("productId").getOrElse("")
  
  // Validate that productId is numeric
  if (!productId.matches("\\d+")) {
    throw new IllegalArgumentException("Invalid product ID")
  }
  
  val xmlData = "<inventory><product id='1'><price>100</price></product><product id='2'><price>200</price></product></inventory>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ok: scala-xpath-injection
  val price = xPath.evaluate("/inventory/product[@id=" + productId + "]/price/text()", doc)
  
  price
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_8(request: akka.http.scaladsl.model.HttpRequest): NodeList = {
  val tag = request.uri.query().get("tag").getOrElse("")
  
  // Use parameterized XPath with variables
  val xmlData = "<blog><post><tag>scala</tag><content>Scala tutorial</content></post><post><tag>java</tag><content>Java guide</content></post></blog>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  val expr = xPath.compile("/blog/post[tag=$tagParam]")
  
  // Create variable bindings
  val variables = new XPathVariableResolver {
    override def resolveVariable(variableName: javax.xml.namespace.QName): AnyRef = {
      if (variableName.getLocalPart == "tagParam") tag else null
    }
  }
  
  xPath.setXPathVariableResolver(variables)
  // ok: scala-xpath-injection
  val result = expr.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
  
  result
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_9(request: play.api.mvc.Request[AnyContent]): String = {
  val attribute = request.body.asFormUrlEncoded.get("attribute").head
  val value = request.body.asFormUrlEncoded.get("value").head
  
  // Sanitize inputs
  val sanitizedAttr = StringEscapeUtils.escapeXml11(attribute)
  val sanitizedVal = StringEscapeUtils.escapeXml11(value)
  
  val xmlData = "<data><entry key='name' value='John'/><entry key='age' value='30'/></data>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ok: scala-xpath-injection
  val result = xPath.evaluate(s"/data/entry[@key='$sanitizedAttr' and @value='$sanitizedVal']/@key", doc)
  
  result
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_10(request: play.api.mvc.Request[AnyContent]): NodeList = {
  // Instead of accepting arbitrary XPath, use predefined queries
  val queryType = request.getQueryString("queryType").getOrElse("")
  
  val xmlData = "<config><setting name='timeout' value='30'/><setting name='retries' value='3'/></config>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  
  val expr = queryType match {
    case "all" => xPath.compile("/config/setting")
    case "timeout" => xPath.compile("/config/setting[@name='timeout']")
    case "retries" => xPath.compile("/config/setting[@name='retries']")
    case _ => xPath.compile("/config")
  }
  
  // ok: scala-xpath-injection
  expr.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_11(request: play.api.mvc.Request[AnyContent]): String = {
  val elementName = request.headers.get("X-Element").getOrElse("")
  
  // Whitelist validation
  val validElements = Set("element1", "element2")
  if (!validElements.contains(elementName)) {
    throw new IllegalArgumentException("Invalid element name")
  }
  
  val xmlData = "<root><element1>Value1</element1><element2>Value2</element2></root>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ok: scala-xpath-injection
  val result = xPath.evaluate("/root/" + elementName + "/text()", doc)
  
  result
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_12(request: akka.http.scaladsl.model.HttpRequest): NodeList = {
  val operator = request.uri.query().get("operator").getOrElse("")
  val value = request.uri.query().get("value").getOrElse("")
  
  // Validate operator and value
  val validOperators = Set("=", "<", ">", "<=", ">=")
  if (!validOperators.contains(operator)) {
    throw new IllegalArgumentException("Invalid operator")
  }
  
  if (!value.matches("\\d+")) {
    throw new IllegalArgumentException("Value must be numeric")
  }
  
  val xmlData = "<numbers><number value='10'/><number value='20'/><number value='30'/></numbers>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ok: scala-xpath-injection
  val expr = xPath.compile(s"/numbers/number[@value $operator $value]")
  
  expr.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_13(request: play.api.mvc.Request[AnyContent]): String = {
  val namespace = request.getQueryString("ns").getOrElse("")
  val element = request.getQueryString("element").getOrElse("")
  
  // Whitelist validation for namespace and element
  val validNamespaces = Set("ns1", "ns2")
  val validElements = Set("elem", "item")
  
  if (!validNamespaces.contains(namespace) || !validElements.contains(element)) {
    throw new IllegalArgumentException("Invalid namespace or element")
  }
  
  val xmlData = "<root xmlns:ns1='http://example.com/ns1'><ns1:elem>Value</ns1:elem></root>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  // ok: scala-xpath-injection
  val result = xPath.evaluate(s"/root/$namespace:$element/text()", doc)
  
  result
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_14(request: play.api.mvc.Request[AnyContent]): NodeList = {
  val position = request.body.asJson.get("position").as[String]
  
  // Use parameterized XPath with variables
  val xmlData = "<team><member position='developer'>Alice</member><member position='manager'>Bob</member></team>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  val expr = xPath.compile("/team/member[@position=$pos]")
  
  // Create variable bindings
  val variables = new XPathVariableResolver {
    override def resolveVariable(variableName: javax.xml.namespace.QName): AnyRef = {
      if (variableName.getLocalPart == "pos") position else null
    }
  }
  
  xPath.setXPathVariableResolver(variables)
  // ok: scala-xpath-injection
  val result = expr.evaluate(doc, XPathConstants.NODESET).asInstanceOf[NodeList]
  
  result
}
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

def good_case_15(request: play.api.mvc.Request[AnyContent]): String = {
  // Instead of accepting arbitrary conditions, use predefined conditions
  val conditionType = request.getQueryString("conditionType").getOrElse("")
  
  val xmlData = "<data><item type='A' value='1'/><item type='B' value='2'/></data>"
  val factory = DocumentBuilderFactory.newInstance()
  val builder = factory.newDocumentBuilder()
  val doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()))
  
  val xPath = XPathFactory.newInstance().newXPath()
  
  val condition = conditionType match {
    case "typeA" => "@type='A'"
    case "typeB" => "@type='B'"
    case "valueGreaterThan1" => "@value>1"
    case _ => "1=1" // Default condition that selects all items
  }
  
  // ok: scala-xpath-injection
  val result = xPath.evaluate(s"/data/item[$condition]/@value", doc)
  
  result
}
// {/fact}

// Helper classes for the examples
case class FakeHttpHeaders(headers: Seq[(String, Seq[String])]) extends play.api.mvc.Headers {
  override def toMap: Map[String, Seq[String]] = headers.toMap
  override def getAll(key: String): Seq[String] = headers.find(_._1.equalsIgnoreCase(key)).map(_._2).getOrElse(Seq.empty)
  override def get(key: String): Option[String] = getAll(key).headOption
  override def keys: Set[String] = headers.map(_._1).toSet
  override def headers: Seq[(String, String)] = headers.flatMap { case (k, vs) => vs.map(v => (k, v)) }
}

case class FakeRequestBody() extends play.api.mvc.AnyContent {
  override def asFormUrlEncoded: Option[Map[String, Seq[String]]] = None
  override def asJson: Option[play.api.libs.json.JsValue] = None
  override def asXml: Option[scala.xml.NodeSeq] = None
  override def asText: Option[String] = None
  override def asRaw: Option[play.api.mvc.RawBuffer] = None
  override def asMultipartFormData: Option[play.api.mvc.MultipartFormData[play.api.libs.Files.TemporaryFile]] = None
}