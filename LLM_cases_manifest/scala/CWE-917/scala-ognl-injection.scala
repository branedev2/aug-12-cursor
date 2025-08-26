import scala.collection.JavaConverters._
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.apache.struts2.ServletActionContext
import ognl.Ognl
import ognl.OgnlContext
import java.util.HashMap
import play.api.mvc._
import play.api.mvc.Results._
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation._
import org.springframework.http.ResponseEntity
import java.util.Properties
import scala.io.Source
import java.io.File
// {fact rule=expression-language-injection@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(request: HttpServletRequest): Any = {
  val expression = request.getParameter("expression")
  val context = new OgnlContext()
  
  // ruleid: scala-ognl-injection
  val result = Ognl.getValue(expression, context, context.getRoot)
  
  result
}
// {/fact}
// {fact rule=expression-language-injection@v1.0 defects=1}

def bad_case_2(request: HttpServletRequest): Any = {
  val userInput = request.getParameter("query")
  val ognlContext = new OgnlContext()
  val root = new HashMap[String, Object]()
  ognlContext.setRoot(root)
  
  try {
    // ruleid: scala-ognl-injection
    val parsedExpression = Ognl.parseExpression(userInput)
    Ognl.getValue(parsedExpression, ognlContext, root)
  } catch {
    case e: Exception => e.getMessage
  }
}
// {/fact}
// {fact rule=expression-language-injection@v1.0 defects=1}

def bad_case_3(request: HttpServletRequest): String = {
  val expression = request.getParameter("expr")
  val context = Ognl.createDefaultContext(null)
  
  // ruleid: scala-ognl-injection
  val result = Ognl.getValue(expression, context, null)
  
  result.toString
}
// {/fact}

def bad_case_4(): Action[AnyContent] = Action { request =>
  val userInput = request.queryString.get("expression").flatMap(_.headOption).getOrElse("")
  val context = new OgnlContext()
  
  try {
    // ruleid: scala-ognl-injection
    val parsedExpr = Ognl.parseExpression(userInput)
    val result = Ognl.getValue(parsedExpr, context, context.getRoot)
    Ok(s"Result: $result")
  } catch {
    case e: Exception => BadRequest(s"Error: ${e.getMessage}")
  }
}
// {fact rule=expression-language-injection@v1.0 defects=1}

def bad_case_5(request: HttpServletRequest): Any = {
  val userExpression = request.getParameter("ognl")
  val context = new OgnlContext()
  val root = new Object()
  context.setRoot(root)
  
  // ruleid: scala-ognl-injection
  Ognl.getValue(userExpression, context, root)
}
// {/fact}

@Controller
class BadController {
  @RequestMapping(Array("/evaluate"))
  def bad_case_6(@RequestParam("expr") expression: String): ResponseEntity[String] = {
    val context = Ognl.createDefaultContext(null)
    
    // ruleid: scala-ognl-injection
    val result = Ognl.getValue(expression, context, null)
    
    ResponseEntity.ok(result.toString)
  }
}
// {fact rule=expression-language-injection@v1.0 defects=1}

def bad_case_7(request: HttpServletRequest): Any = {
  val userInput = request.getHeader("X-Expression")
  val context = new OgnlContext()
  
  // ruleid: scala-ognl-injection
  val node = Ognl.compileExpression(context, context.getRoot, userInput)
  Ognl.getValue(node, context, context.getRoot)
}
// {/fact}

def bad_case_8(): Action[AnyContent] = Action { request =>
  val expression = request.body.asFormUrlEncoded.flatMap(_.get("expression").map(_.head)).getOrElse("")
  val context = new OgnlContext()
  
  try {
    // ruleid: scala-ognl-injection
    val result = Ognl.getValue(expression, context, context.getRoot)
    Ok(s"Evaluated: $result")
  } catch {
    case e: Exception => BadRequest("Invalid expression")
  }
}
// {fact rule=expression-language-injection@v1.0 defects=1}

def bad_case_9(request: HttpServletRequest): Any = {
  val cookie = request.getCookies.find(_.getName == "expression")
  val expression = cookie.map(_.getValue).getOrElse("")
  val context = new OgnlContext()
  
  // ruleid: scala-ognl-injection
  Ognl.getValue(expression, context, context.getRoot)
}
// {/fact}
// {fact rule=expression-language-injection@v1.0 defects=1}

def bad_case_10(request: HttpServletRequest): Any = {
  val userInput = request.getParameter("command")
  val context = Ognl.createDefaultContext(null)
  val root = new HashMap[String, Object]()
  
  // Add some variables to the context
  context.put("user", "admin")
  
  // ruleid: scala-ognl-injection
  Ognl.getValue(userInput, context, root)
}
// {/fact}

def bad_case_11(): Action[AnyContent] = Action { request =>
  val jsonBody = request.body.asJson
  val expression = jsonBody.flatMap(json => (json \ "expression").asOpt[String]).getOrElse("")
  val context = new OgnlContext()
  
  // ruleid: scala-ognl-injection
  val result = Ognl.getValue(expression, context, context.getRoot)
  Ok(s"Result: $result")
}
// {fact rule=expression-language-injection@v1.0 defects=1}

def bad_case_12(request: HttpServletRequest): Any = {
  val referer = request.getHeader("Referer")
  val context = new OgnlContext()
  
  // Extract expression from referer (dangerous!)
  val expression = referer.split("expression=").last
  
  // ruleid: scala-ognl-injection
  Ognl.getValue(expression, context, context.getRoot)
}
// {/fact}
// {fact rule=expression-language-injection@v1.0 defects=1}

def bad_case_13(request: HttpServletRequest): Any = {
  val userAgent = request.getHeader("User-Agent")
  val context = new OgnlContext()
  
  // This is a contrived example but demonstrates the issue
  if (userAgent.contains("OGNL:")) {
    val expression = userAgent.split("OGNL:").last.trim
    // ruleid: scala-ognl-injection
    return Ognl.getValue(expression, context, context.getRoot)
  }
  
  "No expression found"
}
// {/fact}

def bad_case_14(): Action[AnyContent] = Action { request =>
  val path = request.path
  // Extract expression from URL path
  val expression = path.replaceAll("/evaluate/", "")
  val context = new OgnlContext()
  
  // ruleid: scala-ognl-injection
  val result = Ognl.getValue(expression, context, context.getRoot)
  Ok(result.toString)
}
// {fact rule=expression-language-injection@v1.0 defects=1}

def bad_case_15(request: HttpServletRequest): Any = {
  // Read multiple parameters and construct an OGNL expression
  val obj = request.getParameter("object")
  val prop = request.getParameter("property")
  val expression = s"$obj.$prop"
  
  val context = new OgnlContext()
  
  // ruleid: scala-ognl-injection
  Ognl.getValue(expression, context, context.getRoot)
}
// {/fact}
// {fact rule=expression-language-injection@v1.0 defects=0}

// True Negative Examples (Safe Code)

def good_case_1(request: HttpServletRequest): Any = {
  // Using a predefined set of allowed expressions
  val userInput = request.getParameter("expression")
  val allowedExpressions = Set("user.name", "user.role", "user.department")
  
  if (allowedExpressions.contains(userInput)) {
    val context = new OgnlContext()
    // ok: scala-ognl-injection
    val result = Ognl.getValue(userInput, context, context.getRoot)
    result
  } else {
    "Invalid expression"
  }
}
// {/fact}
// {fact rule=expression-language-injection@v1.0 defects=0}

def good_case_2(request: HttpServletRequest): Any = {
  // Using hardcoded expressions instead of user input
  val context = new OgnlContext()
  val root = new HashMap[String, Object]()
  context.setRoot(root)
  
  // ok: scala-ognl-injection
  val parsedExpression = Ognl.parseExpression("user.getDetails()")
  Ognl.getValue(parsedExpression, context, root)
}
// {/fact}

def good_case_3(): Action[AnyContent] = Action { request =>
  // Using a safe, hardcoded expression
  val context = new OgnlContext()
  
  // ok: scala-ognl-injection
  val result = Ognl.getValue("2 + 2", context, context.getRoot)
  Ok(s"Result: $result")
}
// {fact rule=expression-language-injection@v1.0 defects=0}

def good_case_4(request: HttpServletRequest): Any = {
  // Using pattern matching to restrict expressions
  val userInput = request.getParameter("operation")
  
  val safeExpression = userInput match {
    case "add" => "2 + 2"
    case "subtract" => "4 - 2"
    case "multiply" => "2 * 3"
    case _ => "0"
  }
  
  val context = new OgnlContext()
  // ok: scala-ognl-injection
  Ognl.getValue(safeExpression, context, context.getRoot)
}
// {/fact}
// {fact rule=expression-language-injection@v1.0 defects=0}

def good_case_5(request: HttpServletRequest): Any = {
  // Using a validator function to check expressions
  val userInput = request.getParameter("expr")
  
  def isValidExpression(expr: String): Boolean = {
    // Only allow simple arithmetic expressions
    expr.matches("[0-9+\\-*/\\s.()]+")
  }
  
  if (isValidExpression(userInput)) {
    val context = new OgnlContext()
    // ok: scala-ognl-injection
    val result = Ognl.getValue(userInput, context, context.getRoot)
    result
  } else {
    "Invalid expression"
  }
}
// {/fact}

@Controller
class GoodController {
  private val safeExpressions = Map(
    "userDetails" -> "user.details",
    "userRoles" -> "user.roles",
    "companyInfo" -> "company.info"
  )
  
  @RequestMapping(Array("/safe-evaluate"))
  def good_case_6(@RequestParam("exprKey") expressionKey: String): ResponseEntity[String] = {
    val context = Ognl.createDefaultContext(null)
    
    safeExpressions.get(expressionKey) match {
      case Some(safeExpr) =>
        // ok: scala-ognl-injection
        val result = Ognl.getValue(safeExpr, context, null)
        ResponseEntity.ok(result.toString)
      case None =>
        ResponseEntity.badRequest().body("Invalid expression key")
    }
  }
}

def good_case_7(): Action[AnyContent] = Action { request =>
  // Using a predefined expression and only accepting parameters for it
  val id = request.queryString.get("id").flatMap(_.headOption).getOrElse("0")
  
  if (id.matches("\\d+")) {
    val context = new OgnlContext()
    context.put("id", id.toInt)
    
    // ok: scala-ognl-injection
    val result = Ognl.getValue("user.findById(#id)", context, context.getRoot)
    Ok(s"User: $result")
  } else {
    BadRequest("Invalid ID")
  }
}
// {fact rule=expression-language-injection@v1.0 defects=0}

def good_case_8(request: HttpServletRequest): Any = {
  // Using a template with placeholders instead of direct user input
  val userId = request.getParameter("userId")
  
  if (userId.matches("\\d+")) {
    val context = new OgnlContext()
    context.put("id", userId.toInt)
    
    // ok: scala-ognl-injection
    val result = Ognl.getValue("userService.getUserById(#id)", context, context.getRoot)
    result
  } else {
    "Invalid user ID"
  }
}
// {/fact}

def good_case_9(): Action[AnyContent] = Action { request =>
  // Using a builder pattern to construct safe expressions
  case class OgnlExpressionBuilder(private val parts: List[String] = Nil) {
    def withProperty(name: String): OgnlExpressionBuilder = {
      if (name.matches("[a-zA-Z0-9_]+")) {
        OgnlExpressionBuilder(parts :+ name)
      } else {
        this
      }
    }
    
    def build: String = parts.mkString(".")
  }
  
  val property = request.queryString.get("property").flatMap(_.headOption).getOrElse("")
  
  val expression = OgnlExpressionBuilder(List("user"))
    .withProperty(property)
    .build
  
  val context = new OgnlContext()
  // ok: scala-ognl-injection
  val result = Ognl.getValue(expression, context, context.getRoot)
  Ok(s"Result: $result")
}
// {fact rule=expression-language-injection@v1.0 defects=0}

def good_case_10(request: HttpServletRequest): Any = {
  // Using an enum to restrict possible expressions
  object SafeExpressions extends Enumeration {
    val UserName = "user.name"
    val UserEmail = "user.email"
    val UserRole = "user.role"
  }
  
  val userInput = request.getParameter("expr")
  
  val safeExpression = SafeExpressions.values.find(_ == userInput).getOrElse("user.defaultInfo")
  
  val context = new OgnlContext()
  // ok: scala-ognl-injection
  Ognl.getValue(safeExpression, context, context.getRoot)
}
// {/fact}

def good_case_11(): Action[AnyContent] = Action { request =>
  // Using a configuration file to define allowed expressions
  val properties = new Properties()
  properties.load(getClass.getResourceAsStream("/allowed-expressions.properties"))
  
  val expressionKey = request.queryString.get("key").flatMap(_.headOption).getOrElse("")
  val expression = Option(properties.getProperty(expressionKey)).getOrElse("default.expression")
  
  val context = new OgnlContext()
  // ok: scala-ognl-injection
  val result = Ognl.getValue(expression, context, context.getRoot)
  Ok(s"Result: $result")
}
// {fact rule=expression-language-injection@v1.0 defects=0}

def good_case_12(request: HttpServletRequest): Any = {
  // Using a custom DSL that gets translated to safe OGNL
  val userInput = request.getParameter("query")
  
  def translateToDSL(input: String): Option[String] = {
    input match {
      case "get-user-name" => Some("user.name")
      case "get-user-email" => Some("user.email")
      case "get-user-roles" => Some("user.roles")
      case _ => None
    }
  }
  
  translateToDSL(userInput) match {
    case Some(safeExpression) =>
      val context = new OgnlContext()
      // ok: scala-ognl-injection
      Ognl.getValue(safeExpression, context, context.getRoot)
    case None =>
      "Invalid query"
  }
}
// {/fact}
// {fact rule=expression-language-injection@v1.0 defects=0}

def good_case_13(request: HttpServletRequest): Any = {
  // Using a whitelist approach with regex pattern matching
  val userInput = request.getParameter("expression")
  
  // Only allow expressions that access properties on the user object
  val safePattern = "^user\\.(name|email|address|phone|role)$".r
  
  userInput match {
    case safePattern(_) =>
      val context = new OgnlContext()
      // ok: scala-ognl-injection
      Ognl.getValue(userInput, context, context.getRoot)
    case _ =>
      "Invalid expression"
  }
}
// {/fact}

def good_case_14(): Action[AnyContent] = Action { request =>
  // Using a function to generate expressions based on safe inputs
  val entity = request.queryString.get("entity").flatMap(_.headOption).getOrElse("")
  val property = request.queryString.get("property").flatMap(_.headOption).getOrElse("")
  
  def generateSafeExpression(entity: String, property: String): Option[String] = {
    val validEntities = Set("user", "product", "order")
    val validProperties = Set("id", "name", "description", "price", "date")
    
    if (validEntities.contains(entity) && validProperties.contains(property)) {
      Some(s"$entity.$property")
    } else {
      None
    }
  }
  
  generateSafeExpression(entity, property) match {
    case Some(safeExpr) =>
      val context = new OgnlContext()
      // ok: scala-ognl-injection
      val result = Ognl.getValue(safeExpr, context, context.getRoot)
      Ok(s"Result: $result")
    case None =>
      BadRequest("Invalid entity or property")
  }
}
// {fact rule=expression-language-injection@v1.0 defects=0}

def good_case_15(request: HttpServletRequest): Any = {
  // Using a separate service to handle OGNL expressions safely
  val operationType = request.getParameter("operation")
  val id = request.getParameter("id")
  
  class SafeOgnlService {
    private val expressionTemplates = Map(
      "getUserName" -> "userService.findById(%s).getName()",
      "getUserEmail" -> "userService.findById(%s).getEmail()",
      "getProductPrice" -> "productService.findById(%s).getPrice()"
    )
    
    def executeOperation(operation: String, id: String): Any = {
      if (!id.matches("\\d+")) {
        return "Invalid ID"
      }
      
      expressionTemplates.get(operation) match {
        case Some(template) =>
          val expression = template.format(id)
          val context = new OgnlContext()
          // ok: scala-ognl-injection
          Ognl.getValue(expression, context, context.getRoot)
        case None =>
          "Unknown operation"
      }
    }
  }
  
  val service = new SafeOgnlService()
  service.executeOperation(operationType, id)
}
// {/fact}