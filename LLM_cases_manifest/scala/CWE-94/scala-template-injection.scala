import org.apache.velocity.VelocityContext
import org.apache.velocity.app.{Velocity, VelocityEngine}
import freemarker.template.{Configuration, Template, TemplateExceptionHandler}
import org.owasp.encoder.Encode
import java.io.{StringReader, StringWriter}
import java.util.{HashMap => JHashMap, Map => JMap, Properties}
import scala.collection.JavaConverters._
import play.api.mvc._
import play.api.http.HttpVerbs
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import scala.io.Source
import scala.util.{Try, Success, Failure}
// {fact rule=autoescape-disabled@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(request: HttpServletRequest): String = {
  val userTemplate = request.getParameter("template")
  
  val ve = new VelocityEngine()
  ve.init()
  
  val context = new VelocityContext()
  context.put("name", "John")
  
  val writer = new StringWriter()
  // ruleid: scala-template-injection
  ve.evaluate(context, writer, "dynamic_template", userTemplate)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_2(request: HttpServletRequest): String = {
  val userInput = request.getParameter("message")
  
  val ve = new VelocityEngine()
  val props = new Properties()
  props.setProperty("resource.loader", "string")
  props.setProperty("string.resource.loader.class", "org.apache.velocity.runtime.resource.loader.StringResourceLoader")
  ve.init(props)
  
  val context = new VelocityContext()
  context.put("user", "Admin")
  
  val template = s"<div>$userInput</div>#set($$command = 'ls -la')#set($$result = $$runtime.exec($$command))"
  val writer = new StringWriter()
  
  // ruleid: scala-template-injection
  Velocity.evaluate(context, writer, "dynamicTemplate", template)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_3(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val templateContent = request.getParameter("content")
  
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  
  val template = new Template("dynamic_template", new StringReader(templateContent), config)
  val dataModel = new JHashMap[String, Object]()
  dataModel.put("user", "Guest")
  
  val out = response.getWriter
  // ruleid: scala-template-injection
  template.process(dataModel, out)
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_4(request: HttpServletRequest): String = {
  val userTemplate = request.getParameter("template")
  val userName = request.getParameter("name")
  
  val ve = new VelocityEngine()
  ve.init()
  
  val context = new VelocityContext()
  context.put("name", userName)
  
  val writer = new StringWriter()
  // ruleid: scala-template-injection
  ve.mergeTemplate(new StringReader(userTemplate), "dynamic_template", "UTF-8", context, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_5(request: HttpServletRequest): String = {
  val userInput = request.getHeader("X-Template")
  
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  
  val template = new Template("dynamic_template", new StringReader(userInput), config)
  val dataModel = new JHashMap[String, Object]()
  dataModel.put("company", "ACME Corp")
  
  val writer = new StringWriter()
  // ruleid: scala-template-injection
  template.process(dataModel, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_6(request: HttpServletRequest): String = {
  val templateId = request.getParameter("id")
  val templateContent = s"Hello, #set($$cmd='echo vulnerable')#evaluate($$cmd)"
  
  val ve = new VelocityEngine()
  ve.init()
  
  val context = new VelocityContext()
  context.put("id", templateId)
  
  val writer = new StringWriter()
  // ruleid: scala-template-injection
  ve.evaluate(context, writer, templateId, templateContent)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_7(request: HttpServletRequest): String = {
  val cookie = request.getCookies().find(_.getName == "template_data")
  val templateData = cookie.map(_.getValue).getOrElse("")
  
  val ve = new VelocityEngine()
  ve.init()
  
  val context = new VelocityContext()
  context.put("data", Map("key" -> "value").asJava)
  
  val writer = new StringWriter()
  // ruleid: scala-template-injection
  Velocity.evaluate(context, writer, "cookieTemplate", templateData)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_8(request: HttpServletRequest): String = {
  val templatePath = request.getParameter("path")
  val templateContent = Source.fromFile(templatePath).mkString
  
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  
  val template = new Template("file_template", new StringReader(templateContent), config)
  val dataModel = new JHashMap[String, Object]()
  dataModel.put("items", List("item1", "item2").asJava)
  
  val writer = new StringWriter()
  // ruleid: scala-template-injection
  template.process(dataModel, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_9(request: HttpServletRequest): String = {
  val userTemplate = request.getParameter("template")
  val userData = request.getParameter("data").split(",").toList
  
  val ve = new VelocityEngine()
  ve.init()
  
  val context = new VelocityContext()
  context.put("items", userData.asJava)
  
  val writer = new StringWriter()
  // ruleid: scala-template-injection
  ve.evaluate(context, writer, "dynamic_list_template", userTemplate)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_10(request: HttpServletRequest): String = {
  val baseTemplate = "<h1>Welcome</h1>"
  val userContent = request.getParameter("content")
  val fullTemplate = baseTemplate + userContent
  
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  
  val template = new Template("combined_template", new StringReader(fullTemplate), config)
  val dataModel = new JHashMap[String, Object]()
  dataModel.put("user", "Guest")
  
  val writer = new StringWriter()
  // ruleid: scala-template-injection
  template.process(dataModel, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_11(request: HttpServletRequest): String = {
  val templateEngine = request.getParameter("engine")
  val templateContent = request.getParameter("content")
  
  if (templateEngine == "velocity") {
    val ve = new VelocityEngine()
    ve.init()
    
    val context = new VelocityContext()
    context.put("name", "User")
    
    val writer = new StringWriter()
    // ruleid: scala-template-injection
    ve.evaluate(context, writer, "dynamic_template", templateContent)
    
    writer.toString
  } else {
    "Unsupported template engine"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_12(request: HttpServletRequest): String = {
  val userTemplate = request.getParameter("template")
  val dynamicData = Map("key1" -> "value1", "key2" -> "value2")
  
  val ve = new VelocityEngine()
  ve.init()
  
  val context = new VelocityContext()
  dynamicData.foreach { case (k, v) => context.put(k, v) }
  
  val writer = new StringWriter()
  // ruleid: scala-template-injection
  Velocity.evaluate(context, writer, "dynamicTemplate", userTemplate)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_13(request: HttpServletRequest): String = {
  val templateFormat = request.getParameter("format")
  val templateContent = s"<#assign ex='freemarker.template.utility.Execute'?new()>\${ex('$templateFormat')}"
  
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  
  val template = new Template("dynamic_template", new StringReader(templateContent), config)
  val dataModel = new JHashMap[String, Object]()
  
  val writer = new StringWriter()
  // ruleid: scala-template-injection
  template.process(dataModel, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_14(request: HttpServletRequest): String = {
  val userInput = request.getParameter("query")
  val templateContent = s"#set($$result = $$esc.java('$userInput'))"
  
  val ve = new VelocityEngine()
  ve.init()
  
  val context = new VelocityContext()
  
  val writer = new StringWriter()
  // ruleid: scala-template-injection
  ve.evaluate(context, writer, "escapeTemplate", templateContent)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_15(request: HttpServletRequest): String = {
  val part1 = request.getParameter("part1")
  val part2 = request.getParameter("part2")
  val templateContent = part1 + part2
  
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  
  val template = new Template("combined_parts", new StringReader(templateContent), config)
  val dataModel = new JHashMap[String, Object]()
  dataModel.put("app", "MyApp")
  
  val writer = new StringWriter()
  // ruleid: scala-template-injection
  template.process(dataModel, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

// True Negative Examples (Safe Code)

def good_case_1(request: HttpServletRequest): String = {
  val userInput = request.getParameter("message")
  val encodedInput = Encode.forHtml(userInput)
  
  val ve = new VelocityEngine()
  ve.init()
  
  val context = new VelocityContext()
  context.put("message", encodedInput)
  
  val writer = new StringWriter()
  // ok: scala-template-injection
  ve.evaluate(context, writer, "template", "Hello, $message!")
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_2(request: HttpServletRequest): String = {
  val userName = request.getParameter("name")
  val encodedName = Encode.forHtml(userName)
  
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  
  val templateContent = "Hello, ${name}!"
  val template = new Template("static_template", new StringReader(templateContent), config)
  
  val dataModel = new JHashMap[String, Object]()
  dataModel.put("name", encodedName)
  
  val writer = new StringWriter()
  // ok: scala-template-injection
  template.process(dataModel, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_3(request: HttpServletRequest): String = {
  val userId = request.getParameter("id")
  
  val ve = new VelocityEngine()
  ve.init()
  
  val context = new VelocityContext()
  context.put("id", userId)
  
  val staticTemplate = "User ID: $id"
  val writer = new StringWriter()
  
  // ok: scala-template-injection
  ve.evaluate(context, writer, "static_template", staticTemplate)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_4(request: HttpServletRequest): String = {
  val message = request.getParameter("message")
  val encodedMessage = Encode.forHtml(message)
  
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  
  // Using a predefined template with no user input in the template itself
  val templateContent = "<div>Message: ${message}</div>"
  val template = new Template("static_template", new StringReader(templateContent), config)
  
  val dataModel = new JHashMap[String, Object]()
  dataModel.put("message", encodedMessage)
  
  val writer = new StringWriter()
  // ok: scala-template-injection
  template.process(dataModel, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_5(request: HttpServletRequest): String = {
  val userInput = request.getParameter("input")
  val sanitizedInput = Encode.forHtml(userInput)
  
  val ve = new VelocityEngine()
  ve.init()
  
  val context = new VelocityContext()
  context.put("input", sanitizedInput)
  
  // Template is static and predefined
  val staticTemplate = "#if($input.length() > 0) Input: $input #else No input provided #end"
  val writer = new StringWriter()
  
  // ok: scala-template-injection
  Velocity.evaluate(context, writer, "static_template", staticTemplate)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_6(request: HttpServletRequest): String = {
  val items = request.getParameterValues("items")
  val sanitizedItems = items.map(Encode.forHtml)
  
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  
  // Using a predefined template
  val templateContent = "<ul><#list items as item><li>${item}</li></#list></ul>"
  val template = new Template("list_template", new StringReader(templateContent), config)
  
  val dataModel = new JHashMap[String, Object]()
  dataModel.put("items", sanitizedItems)
  
  val writer = new StringWriter()
  // ok: scala-template-injection
  template.process(dataModel, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_7(request: HttpServletRequest): String = {
  val userName = request.getParameter("name")
  val encodedName = Encode.forHtml(userName)
  
  // Using a template from a safe, controlled source
  val templatePath = "templates/welcome.vm"
  
  val ve = new VelocityEngine()
  val props = new Properties()
  props.setProperty("file.resource.loader.path", "/safe/path/")
  ve.init(props)
  
  val context = new VelocityContext()
  context.put("name", encodedName)
  
  val writer = new StringWriter()
  // ok: scala-template-injection
  ve.mergeTemplate(templatePath, "UTF-8", context, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_8(request: HttpServletRequest): String = {
  val userInput = request.getParameter("input")
  val sanitizedInput = Encode.forHtml(userInput)
  
  // Using a predefined template with no user-controlled template logic
  val templateContent = "Hello, ${input}!"
  
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  config.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER)
  
  val template = new Template("static_template", new StringReader(templateContent), config)
  
  val dataModel = new JHashMap[String, Object]()
  dataModel.put("input", sanitizedInput)
  
  val writer = new StringWriter()
  // ok: scala-template-injection
  template.process(dataModel, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_9(request: HttpServletRequest): String = {
  // Using a whitelist of allowed templates
  val templateName = request.getParameter("template")
  val allowedTemplates = Map(
    "welcome" -> "Welcome, $name!",
    "goodbye" -> "Goodbye, $name!",
    "error" -> "Error: $message"
  )
  
  if (!allowedTemplates.contains(templateName)) {
    return "Invalid template"
  }
  
  val templateContent = allowedTemplates(templateName)
  val name = Encode.forHtml(request.getParameter("name"))
  val message = Encode.forHtml(request.getParameter("message"))
  
  val ve = new VelocityEngine()
  ve.init()
  
  val context = new VelocityContext()
  context.put("name", name)
  context.put("message", message)
  
  val writer = new StringWriter()
  // ok: scala-template-injection
  ve.evaluate(context, writer, templateName, templateContent)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_10(request: HttpServletRequest): String = {
  val userInput = request.getParameter("input")
  val sanitizedInput = Encode.forHtml(userInput)
  
  // Using a template with no execution capabilities
  val templateContent = "<#noparse>${userInput}</#noparse>"
  
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  
  val template = new Template("safe_template", new StringReader(templateContent), config)
  
  val dataModel = new JHashMap[String, Object]()
  dataModel.put("userInput", sanitizedInput)
  
  val writer = new StringWriter()
  // ok: scala-template-injection
  template.process(dataModel, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_11(request: HttpServletRequest): String = {
  val message = request.getParameter("message")
  val sanitizedMessage = Encode.forHtml(message)
  
  // Using a restricted Velocity context
  val ve = new VelocityEngine()
  val props = new Properties()
  props.setProperty("runtime.references.strict", "true")
  props.setProperty("velocimacro.permissions.allow.inline", "false")
  ve.init(props)
  
  val context = new VelocityContext()
  context.put("message", sanitizedMessage)
  
  val staticTemplate = "Message: $message"
  val writer = new StringWriter()
  
  // ok: scala-template-injection
  ve.evaluate(context, writer, "static_template", staticTemplate)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_12(request: HttpServletRequest): String = {
  val templateType = request.getParameter("type")
  
  // Using a map of predefined templates
  val templates = Map(
    "welcome" -> "<h1>Welcome</h1><p>Hello, ${user}!</p>",
    "error" -> "<h1>Error</h1><p>${message}</p>",
    "info" -> "<h1>Information</h1><p>${content}</p>"
  )
  
  if (!templates.contains(templateType)) {
    return "Invalid template type"
  }
  
  val templateContent = templates(templateType)
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  
  val template = new Template(templateType, new StringReader(templateContent), config)
  
  val dataModel = new JHashMap[String, Object]()
  dataModel.put("user", Encode.forHtml(request.getParameter("user")))
  dataModel.put("message", Encode.forHtml(request.getParameter("message")))
  dataModel.put("content", Encode.forHtml(request.getParameter("content")))
  
  val writer = new StringWriter()
  // ok: scala-template-injection
  template.process(dataModel, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_13(request: HttpServletRequest): String = {
  val userInput = request.getParameter("input")
  
  // Using a template with no dynamic content
  val staticTemplate = "Static content with no variables or expressions"
  
  val ve = new VelocityEngine()
  ve.init()
  
  val context = new VelocityContext()
  // User input is not used in the template at all
  context.put("unused", userInput)
  
  val writer = new StringWriter()
  // ok: scala-template-injection
  ve.evaluate(context, writer, "static_template", staticTemplate)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_14(request: HttpServletRequest): String = {
  // Using a template validation function before processing
  def isValidTemplate(template: String): Boolean = {
    // Check for potentially dangerous patterns
    !template.contains("#set") && 
    !template.contains("#evaluate") && 
    !template.contains("$runtime") &&
    !template.contains("Execute") &&
    !template.matches(".*\\$\\{.*\\?.*\\}.*")
  }
  
  val templateContent = "Hello, ${name}!"
  
  if (!isValidTemplate(templateContent)) {
    return "Invalid template"
  }
  
  val config = new Configuration(Configuration.VERSION_2_3_30)
  config.setDefaultEncoding("UTF-8")
  
  val template = new Template("validated_template", new StringReader(templateContent), config)
  
  val dataModel = new JHashMap[String, Object]()
  dataModel.put("name", Encode.forHtml(request.getParameter("name")))
  
  val writer = new StringWriter()
  // ok: scala-template-injection
  template.process(dataModel, writer)
  
  writer.toString
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_15(request: HttpServletRequest): String = {
  val userInput = request.getParameter("input")
  val sanitizedInput = Encode.forHtml(userInput)
  
  // Using a custom wrapper to prevent template injection
  class SafeTemplateRenderer(engine: VelocityEngine) {
    def renderSafely(templateContent: String, variables: Map[String, Any]): String = {
      val context = new VelocityContext()
      variables.foreach { case (k, v) => context.put(k, v) }
      
      val writer = new StringWriter()
      engine.evaluate(context, writer, "safe_template", templateContent)
      writer.toString
    }
  }
  
  val ve = new VelocityEngine()
  ve.init()
  
  val renderer = new SafeTemplateRenderer(ve)
  
  // ok: scala-template-injection
  renderer.renderSafely("Hello, $input!", Map("input" -> sanitizedInput))
}
// {/fact}