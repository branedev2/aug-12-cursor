import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import javax.el.{ExpressionFactory, ValueExpression}
import javax.faces.context.FacesContext
import org.apache.el.ExpressionFactoryImpl
import javax.el.ELContext
import org.owasp.encoder.Encode
import scala.collection.JavaConverters._
import play.api.mvc._
import play.api.http._
import javax.servlet.jsp.JspFactory
import javax.servlet.jsp.PageContext
// {fact rule=autoescape-disabled@v1.0 defects=1}

// True Positives (Vulnerable Code)

def bad_case_1(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("expression")
  val factory = ExpressionFactory.newInstance()
  val context = FacesContext.getCurrentInstance().getELContext()
  
  // ruleid: scala-el-injection
  val expression = factory.createValueExpression(context, "${" + userInput + "}", classOf[Object])
  val result = expression.getValue(context)
  response.getWriter.println(result)
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_2(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("command")
  val factory = new ExpressionFactoryImpl()
  val context = FacesContext.getCurrentInstance().getELContext()
  
  // ruleid: scala-el-injection
  val expression = factory.createValueExpression(context, "#{" + userInput + "}", classOf[String])
  val result = expression.getValue(context)
  response.getWriter.println("Result: " + result)
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_3(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val factory = JspFactory.getDefaultFactory()
  val pageContext = factory.getPageContext(null, request, response, null, true, 8192, true)
  val elContext = pageContext.getELContext()
  val expressionFactory = JspFactory.getDefaultFactory().getJspApplicationContext(request.getServletContext()).getExpressionFactory()
  
  val userInput = request.getHeader("X-Expression")
  
  // ruleid: scala-el-injection
  val valueExpression = expressionFactory.createValueExpression(elContext, "${" + userInput + "}", classOf[Object])
  val result = valueExpression.getValue(elContext)
  response.getWriter.println(result)
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_4(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val cookie = request.getCookies().find(_.getName == "userExpression")
  val userInput = if (cookie.isDefined) cookie.get.getValue else ""
  
  val factory = ExpressionFactory.newInstance()
  val context = FacesContext.getCurrentInstance().getELContext()
  
  // ruleid: scala-el-injection
  val expression = factory.createValueExpression(context, "${" + userInput + ".toString()}", classOf[String])
  val result = expression.getValue(context)
  response.getWriter.println(result)
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_5(request: HttpServletRequest, elContext: ELContext): Unit = {
  val userInput = request.getParameter("expr")
  val factory = new ExpressionFactoryImpl()
  
  if (userInput != null && userInput.length > 0) {
    // ruleid: scala-el-injection
    val methodExpression = factory.createMethodExpression(elContext, "${" + userInput + "}", classOf[Object], Array[Class[_]]())
    val result = methodExpression.invoke(elContext, Array[Object]())
    println(s"Result: $result")
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_6(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("query")
  val factory = ExpressionFactory.newInstance()
  val context = FacesContext.getCurrentInstance().getELContext()
  
  val expressionStr = "${" + userInput + "}"
  // ruleid: scala-el-injection
  val expression = factory.createValueExpression(context, expressionStr, classOf[Object])
  val result = expression.getValue(context)
  response.getWriter.println(result)
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_7(request: HttpServletRequest, elContext: ELContext): Unit = {
  val expressionFactory = ExpressionFactory.newInstance()
  val userInput = request.getParameter("code")
  
  try {
    // ruleid: scala-el-injection
    val valueExpression = expressionFactory.createValueExpression(elContext, "#{ " + userInput + " }", classOf[Object])
    val result = valueExpression.getValue(elContext)
    println(s"Evaluated expression result: $result")
  } catch {
    case e: Exception => e.printStackTrace()
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_8(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("expression")
  val factory = JspFactory.getDefaultFactory()
  val pageContext = factory.getPageContext(null, request, response, null, true, 8192, true)
  val elContext = pageContext.getELContext()
  val expressionFactory = JspFactory.getDefaultFactory().getJspApplicationContext(request.getServletContext()).getExpressionFactory()
  
  if (userInput != null) {
    val prefix = "${"
    val suffix = "}"
    // ruleid: scala-el-injection
    val valueExpression = expressionFactory.createValueExpression(elContext, prefix + userInput + suffix, classOf[Object])
    val result = valueExpression.getValue(elContext)
    response.getWriter.println(result)
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_9(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("expr")
  val factory = ExpressionFactory.newInstance()
  val context = FacesContext.getCurrentInstance().getELContext()
  
  val sb = new StringBuilder()
  sb.append("${")
  sb.append(userInput)
  sb.append("}")
  
  // ruleid: scala-el-injection
  val expression = factory.createValueExpression(context, sb.toString(), classOf[Object])
  val result = expression.getValue(context)
  response.getWriter.println(result)
}
// {/fact}

def bad_case_10(request: HttpServletRequest, elContext: ELContext): Unit = {
  val userInput = request.getParameter("expression")
  val factory = new ExpressionFactoryImpl()
  
  val expressionStr = if (userInput.startsWith("${")) {
    userInput
  } else {
    "${" + userInput + "}"
  }
  
  // ruleid: scala-el-injection
  val valueExpression = factory.createValueExpression(elContext, expressionStr, classOf[Object])
  val result = valueExpression.getValue(elContext)
  println(s"Result: $result")
}

def bad_case_11(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("formula")
  val factory = ExpressionFactory.newInstance()
  val context = FacesContext.getCurrentInstance().getELContext()
  
  val template = "#{%s}"
  val expressionStr = template.format(userInput)
  
  // ruleid: scala-el-injection
  val expression = factory.createValueExpression(context, expressionStr, classOf[Object])
  val result = expression.getValue(context)
  response.getWriter.println(result)
}

def bad_case_12(request: HttpServletRequest, elContext: ELContext): Unit = {
  val parts = List("${", request.getParameter("expr"), "}")
  val expressionStr = parts.mkString
  val factory = ExpressionFactory.newInstance()
  
  // ruleid: scala-el-injection
  val valueExpression = factory.createValueExpression(elContext, expressionStr, classOf[Object])
  val result = valueExpression.getValue(elContext)
  println(s"Evaluated to: $result")
}

def bad_case_13(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("command")
  val factory = ExpressionFactory.newInstance()
  val context = FacesContext.getCurrentInstance().getELContext()
  
  if (userInput != null && userInput.length > 0) {
    val prefix = "${"
    val suffix = "}"
    val expressionStr = prefix + userInput + suffix
    
    // ruleid: scala-el-injection
    val expression = factory.createValueExpression(context, expressionStr, classOf[Object])
    val result = expression.getValue(context)
    response.getWriter.println(result)
  }
}

def bad_case_14(request: HttpServletRequest, elContext: ELContext): Unit = {
  val userInput = request.getParameter("code")
  val factory = new ExpressionFactoryImpl()
  
  val expressionBuilder = new StringBuilder()
  expressionBuilder.append("${")
  expressionBuilder.append(userInput)
  expressionBuilder.append("}")
  
  // ruleid: scala-el-injection
  val valueExpression = factory.createValueExpression(elContext, expressionBuilder.toString(), classOf[Object])
  val result = valueExpression.getValue(elContext)
  println(s"Result: $result")
}

def bad_case_15(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("expression")
  val factory = JspFactory.getDefaultFactory()
  val pageContext = factory.getPageContext(null, request, response, null, true, 8192, true)
  val elContext = pageContext.getELContext()
  val expressionFactory = JspFactory.getDefaultFactory().getJspApplicationContext(request.getServletContext()).getExpressionFactory()
  
  val expressionTemplate = "${%s}"
  val expressionStr = expressionTemplate.format(userInput)
  
  // ruleid: scala-el-injection
  val valueExpression = expressionFactory.createValueExpression(elContext, expressionStr, classOf[Object])
  val result = valueExpression.getValue(elContext)
  response.getWriter.println(result)
}

// True Negatives (Safe Code)

def good_case_1(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("expression")
  val factory = ExpressionFactory.newInstance()
  val context = FacesContext.getCurrentInstance().getELContext()
  
  // ok: scala-el-injection
  val sanitizedInput = Encode.forHtml(userInput)
  val expression = factory.createValueExpression(context, "${" + sanitizedInput + "}", classOf[Object])
  val result = expression.getValue(context)
  response.getWriter.println(result)
}

def good_case_2(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("command")
  
  // Using a whitelist approach
  val allowedCommands = Set("sum", "multiply", "divide", "subtract")
  
  if (allowedCommands.contains(userInput)) {
    val factory = new ExpressionFactoryImpl()
    val context = FacesContext.getCurrentInstance().getELContext()
    
    // ok: scala-el-injection
    val expression = factory.createValueExpression(context, "#{calculator." + userInput + "}", classOf[String])
    val result = expression.getValue(context)
    response.getWriter.println("Result: " + result)
  } else {
    response.getWriter.println("Invalid command")
  }
}

def good_case_3(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val factory = JspFactory.getDefaultFactory()
  val pageContext = factory.getPageContext(null, request, response, null, true, 8192, true)
  val elContext = pageContext.getELContext()
  val expressionFactory = JspFactory.getDefaultFactory().getJspApplicationContext(request.getServletContext()).getExpressionFactory()
  
  val userInput = request.getHeader("X-Expression")
  
  // Using static expressions instead of user input
  // ok: scala-el-injection
  val valueExpression = expressionFactory.createValueExpression(elContext, "${user.name}", classOf[Object])
  val result = valueExpression.getValue(elContext)
  response.getWriter.println(result)
}

def good_case_4(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val cookie = request.getCookies().find(_.getName == "userExpression")
  val userInput = if (cookie.isDefined) cookie.get.getValue else ""
  
  // Validate input against a pattern
  val validPattern = "^[a-zA-Z0-9_.]+$".r
  
  if (validPattern.matches(userInput)) {
    val factory = ExpressionFactory.newInstance()
    val context = FacesContext.getCurrentInstance().getELContext()
    
    // ok: scala-el-injection
    val expression = factory.createValueExpression(context, "${" + userInput + ".toString()}", classOf[String])
    val result = expression.getValue(context)
    response.getWriter.println(result)
  } else {
    response.getWriter.println("Invalid input")
  }
}

def good_case_5(request: HttpServletRequest, elContext: ELContext): Unit = {
  val userInput = request.getParameter("expr")
  
  // Using predefined expressions instead of user input
  val factory = new ExpressionFactoryImpl()
  
  // ok: scala-el-injection
  val methodExpression = factory.createMethodExpression(elContext, "${bean.calculateTotal()}", classOf[Object], Array[Class[_]]())
  val result = methodExpression.invoke(elContext, Array[Object]())
  println(s"Result: $result")
}

def good_case_6(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("query")
  
  // Using a map of predefined expressions
  val allowedExpressions = Map(
    "username" -> "${user.name}",
    "email" -> "${user.email}",
    "age" -> "${user.age}"
  )
  
  val expressionStr = allowedExpressions.getOrElse(userInput, "${user.defaultProperty}")
  val factory = ExpressionFactory.newInstance()
  val context = FacesContext.getCurrentInstance().getELContext()
  
  // ok: scala-el-injection
  val expression = factory.createValueExpression(context, expressionStr, classOf[Object])
  val result = expression.getValue(context)
  response.getWriter.println(result)
}

def good_case_7(request: HttpServletRequest, elContext: ELContext): Unit = {
  val expressionFactory = ExpressionFactory.newInstance()
  val userInput = request.getParameter("code")
  
  // Sanitize and validate input
  val sanitizedInput = Encode.forHtml(userInput)
  val validPattern = "^[a-zA-Z0-9_.]+$".r
  
  try {
    if (validPattern.matches(sanitizedInput)) {
      // ok: scala-el-injection
      val valueExpression = expressionFactory.createValueExpression(elContext, "#{ calculator." + sanitizedInput + " }", classOf[Object])
      val result = valueExpression.getValue(elContext)
      println(s"Evaluated expression result: $result")
    } else {
      println("Invalid input pattern")
    }
  } catch {
    case e: Exception => e.printStackTrace()
  }
}

def good_case_8(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  // Using hardcoded expressions instead of user input
  val factory = JspFactory.getDefaultFactory()
  val pageContext = factory.getPageContext(null, request, response, null, true, 8192, true)
  val elContext = pageContext.getELContext()
  val expressionFactory = JspFactory.getDefaultFactory().getJspApplicationContext(request.getServletContext()).getExpressionFactory()
  
  // ok: scala-el-injection
  val valueExpression = expressionFactory.createValueExpression(elContext, "${user.preferences.theme}", classOf[Object])
  val result = valueExpression.getValue(elContext)
  response.getWriter.println(result)
}

def good_case_9(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("expr")
  
  // Validate against a whitelist of allowed expressions
  val allowedExpressions = Set("user.name", "user.email", "user.role")
  
  if (allowedExpressions.contains(userInput)) {
    val factory = ExpressionFactory.newInstance()
    val context = FacesContext.getCurrentInstance().getELContext()
    
    // ok: scala-el-injection
    val expression = factory.createValueExpression(context, "${" + userInput + "}", classOf[Object])
    val result = expression.getValue(context)
    response.getWriter.println(result)
  } else {
    response.getWriter.println("Invalid expression")
  }
}

def good_case_10(request: HttpServletRequest, elContext: ELContext): Unit = {
  // Using a predefined expression template with validated parameters
  val operation = request.getParameter("operation")
  val allowedOperations = Set("add", "subtract", "multiply", "divide")
  
  if (allowedOperations.contains(operation)) {
    val factory = new ExpressionFactoryImpl()
    
    // ok: scala-el-injection
    val valueExpression = factory.createValueExpression(elContext, "${calculator." + operation + "(param1, param2)}", classOf[Object])
    val result = valueExpression.getValue(elContext)
    println(s"Result: $result")
  } else {
    println("Invalid operation")
  }
}

def good_case_11(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  // Using a fixed set of expressions based on user selection
  val userChoice = request.getParameter("choice")
  val factory = ExpressionFactory.newInstance()
  val context = FacesContext.getCurrentInstance().getELContext()
  
  val expressionStr = userChoice match {
    case "name" => "${user.fullName}"
    case "email" => "${user.emailAddress}"
    case "phone" => "${user.phoneNumber}"
    case _ => "${user.defaultContact}"
  }
  
  // ok: scala-el-injection
  val expression = factory.createValueExpression(context, expressionStr, classOf[Object])
  val result = expression.getValue(context)
  response.getWriter.println(result)
}

def good_case_12(request: HttpServletRequest, elContext: ELContext): Unit = {
  val userInput = request.getParameter("property")
  
  // Sanitize and validate input against strict pattern
  val sanitizedInput = Encode.forHtml(userInput)
  val validPropertyPattern = "^[a-zA-Z][a-zA-Z0-9]*$".r
  
  if (validPropertyPattern.matches(sanitizedInput)) {
    val factory = ExpressionFactory.newInstance()
    
    // ok: scala-el-injection
    val valueExpression = factory.createValueExpression(elContext, "${user." + sanitizedInput + "}", classOf[Object])
    val result = valueExpression.getValue(elContext)
    println(s"Property value: $result")
  } else {
    println("Invalid property name")
  }
}

def good_case_13(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  // Using a fixed expression with parameters from request
  val id = request.getParameter("id")
  
  // Validate id is numeric
  if (id.matches("\\d+")) {
    val factory = ExpressionFactory.newInstance()
    val context = FacesContext.getCurrentInstance().getELContext()
    
    // Set the id as a variable in the context
    context.asInstanceOf[javax.el.StandardELContext].getVariableMapper.setVariable(
      "userId", 
      factory.createValueExpression(id, classOf[String])
    )
    
    // ok: scala-el-injection
    val expression = factory.createValueExpression(context, "${userService.findById(userId)}", classOf[Object])
    val result = expression.getValue(context)
    response.getWriter.println(result)
  } else {
    response.getWriter.println("Invalid ID format")
  }
}

def good_case_14(request: HttpServletRequest, elContext: ELContext): Unit = {
  val userInput = request.getParameter("code")
  
  // Instead of using user input in EL, process it directly
  try {
    // ok: scala-el-injection
    // Use a fixed expression that calls a method to process the user input safely
    val factory = new ExpressionFactoryImpl()
    val valueExpression = factory.createValueExpression(elContext, "${safeEvaluator.process()}", classOf[Object])
    
    // Set the user input as a variable in the context
    elContext.asInstanceOf[javax.el.StandardELContext].getVariableMapper.setVariable(
      "userCode", 
      factory.createValueExpression(userInput, classOf[String])
    )
    
    val result = valueExpression.getValue(elContext)
    println(s"Result: $result")
  } catch {
    case e: Exception => e.printStackTrace()
  }
}

def good_case_15(request: HttpServletRequest, response: HttpServletResponse): Unit = {
  val userInput = request.getParameter("expression")
  
  // Instead of using EL for user input, use a domain-specific parser
  val factory = JspFactory.getDefaultFactory()
  val pageContext = factory.getPageContext(null, request, response, null, true, 8192, true)
  val elContext = pageContext.getELContext()
  val expressionFactory = JspFactory.getDefaultFactory().getJspApplicationContext(request.getServletContext()).getExpressionFactory()
  
  // ok: scala-el-injection
  // Use a fixed EL expression that calls a method to safely evaluate user input
  val valueExpression = expressionFactory.createValueExpression(elContext, "${safeParser.evaluate()}", classOf[Object])
  
  // Set the user input as a variable in the context
  elContext.asInstanceOf[javax.el.StandardELContext].getVariableMapper.setVariable(
    "userExpression", 
    expressionFactory.createValueExpression(userInput, classOf[String])
  )
  
  val result = valueExpression.getValue(elContext)
  response.getWriter.println(result)
}