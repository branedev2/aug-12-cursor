// Import necessary libraries
import org.springframework.expression.ExpressionParser
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.expression.spel.support.StandardEvaluationContext
import org.owasp.esapi.ESAPI
import play.api.mvc._
import play.api.http._
import scala.concurrent.Future
import javax.inject.Inject
import play.api.libs.json._
import scala.io.Source
import scala.util.Try
import scala.util.Success
import scala.util.Failure

// Controller for handling HTTP requests
class ExpressionController @Inject()(cc: ControllerComponents) extends AbstractController(cc) {

  // True positive examples (vulnerable code)
  
  def bad_case_1() = Action { request =>
    val userInput = request.getQueryString("expr").getOrElse("")
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    // ruleid: scala-parse-expression
    val expression = parser.parseExpression(userInput)
    val result = expression.getValue(context)
    Ok(s"Result: $result")
  }

  def bad_case_2() = Action { request =>
    val userInput = request.body.asFormUrlEncoded.get("command").headOption.getOrElse("")
    val parser = new SpelExpressionParser()
    // ruleid: scala-parse-expression
    val expression = parser.parseExpression(userInput)
    val result = expression.getValue()
    Ok(s"Executed: $result")
  }

  def bad_case_3() = Action { request =>
    val jsonBody = request.body.asJson.getOrElse(Json.obj())
    val expressionText = (jsonBody \ "expression").asOpt[String].getOrElse("")
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    // ruleid: scala-parse-expression
    val expression = parser.parseExpression(expressionText)
    val result = expression.getValue(context, classOf[String])
    Ok(s"Evaluated: $result")
  }

  def bad_case_4() = Action { request =>
    val headerValue = request.headers.get("X-Expression").getOrElse("")
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    context.setVariable("header", headerValue)
    // ruleid: scala-parse-expression
    val expr = parser.parseExpression("#header")
    val result = expr.getValue(context)
    Ok(s"Header expression result: $result")
  }

  def bad_case_5() = Action { request =>
    val cookieValue = request.cookies.get("userExpression").map(_.value).getOrElse("")
    val parser = new SpelExpressionParser()
    // ruleid: scala-parse-expression
    val expression = parser.parseExpression(cookieValue)
    val result = expression.getValue()
    Ok(s"Cookie expression result: $result")
  }

  def bad_case_6() = Action { request =>
    val userInput = request.getQueryString("calc").getOrElse("")
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    
    try {
      // ruleid: scala-parse-expression
      val expression = parser.parseExpression(userInput)
      val result = expression.getValue(context)
      Ok(s"Calculation result: $result")
    } catch {
      case e: Exception => BadRequest(s"Invalid expression: ${e.getMessage}")
    }
  }

  def bad_case_7() = Action { request =>
    val path = request.path
    val expressionText = path.substring(path.lastIndexOf("/") + 1)
    val parser = new SpelExpressionParser()
    // ruleid: scala-parse-expression
    val expression = parser.parseExpression(expressionText)
    val result = expression.getValue()
    Ok(s"Path expression result: $result")
  }

  def bad_case_8() = Action { request =>
    val userInput = request.getQueryString("expr").getOrElse("")
    val processedInput = userInput.replaceAll("script", "") // Insufficient sanitization
    val parser = new SpelExpressionParser()
    // ruleid: scala-parse-expression
    val expression = parser.parseExpression(processedInput)
    val result = expression.getValue()
    Ok(s"Processed result: $result")
  }

  def bad_case_9() = Action { request =>
    val formData = request.body.asFormUrlEncoded
    val expressions = formData.getOrElse("expressions", Seq.empty).toList
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    
    val results = expressions.map { expr =>
      // ruleid: scala-parse-expression
      val expression = parser.parseExpression(expr)
      expression.getValue(context).toString
    }
    
    Ok(s"Multiple results: ${results.mkString(", ")}")
  }

  def bad_case_10() = Action { request =>
    val userInput = request.getQueryString("template").getOrElse("")
    val data = Map("name" -> "John", "age" -> 30)
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext(data)
    
    // ruleid: scala-parse-expression
    val expression = parser.parseExpression(userInput)
    val result = expression.getValue(context)
    Ok(s"Template result: $result")
  }

  def bad_case_11() = Action { request =>
    val userInput = request.body.asText.getOrElse("")
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    
    if (userInput.contains("System")) {
      BadRequest("Potential malicious input detected")
    } else {
      // ruleid: scala-parse-expression
      val expression = parser.parseExpression(userInput)
      val result = expression.getValue(context)
      Ok(s"Text body result: $result")
    }
  }

  def bad_case_12() = Action { request =>
    val referer = request.headers.get("Referer").getOrElse("")
    val queryParam = if (referer.contains("?")) {
      referer.substring(referer.indexOf("?") + 1)
    } else ""
    
    val parser = new SpelExpressionParser()
    // ruleid: scala-parse-expression
    val expression = parser.parseExpression(queryParam)
    val result = expression.getValue()
    Ok(s"Referer param result: $result")
  }

  def bad_case_13() = Action { request =>
    val userAgent = request.headers.get("User-Agent").getOrElse("")
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    context.setVariable("agent", userAgent)
    
    // ruleid: scala-parse-expression
    val expression = parser.parseExpression("'User agent: ' + #agent")
    val result = expression.getValue(context)
    Ok(s"Result: $result")
  }

  def bad_case_14() = Action { request =>
    val userInput = request.getQueryString("expr").getOrElse("")
    val parser = new SpelExpressionParser()
    
    def processExpression(expr: String): Any = {
      // ruleid: scala-parse-expression
      val expression = parser.parseExpression(expr)
      expression.getValue()
    }
    
    val result = processExpression(userInput)
    Ok(s"Nested function result: $result")
  }

  def bad_case_15() = Action { request =>
    val jsonBody = request.body.asJson.getOrElse(Json.obj())
    val config = (jsonBody \ "config").asOpt[JsObject].getOrElse(Json.obj())
    val expressionText = (config \ "expression").asOpt[String].getOrElse("")
    
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    
    // ruleid: scala-parse-expression
    val expression = parser.parseExpression(expressionText)
    val result = expression.getValue(context)
    Ok(s"Config expression result: $result")
  }

  // True negative examples (safe code)
  
  def good_case_1() = Action { request =>
    val userInput = request.getQueryString("expr").getOrElse("")
    val sanitizedInput = ESAPI.encoder().encodeForJava(userInput)
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    // ok: scala-parse-expression
    val expression = parser.parseExpression(sanitizedInput)
    val result = expression.getValue(context)
    Ok(s"Result: $result")
  }

  def good_case_2() = Action { request =>
    val parser = new SpelExpressionParser()
    // ok: scala-parse-expression
    val expression = parser.parseExpression("'Hello, ' + 'World!'")
    val result = expression.getValue()
    Ok(s"Static expression result: $result")
  }

  def good_case_3() = Action { request =>
    val userInput = request.body.asFormUrlEncoded.get("number").headOption.getOrElse("0")
    val sanitizedInput = Try(userInput.toInt).getOrElse(0).toString
    val parser = new SpelExpressionParser()
    // ok: scala-parse-expression
    val expression = parser.parseExpression(sanitizedInput)
    val result = expression.getValue()
    Ok(s"Numeric result: $result")
  }

  def good_case_4() = Action { request =>
    val allowedExpressions = Map(
      "add" -> "1 + 1",
      "subtract" -> "2 - 1",
      "multiply" -> "2 * 2"
    )
    
    val userChoice = request.getQueryString("operation").getOrElse("")
    val expressionText = allowedExpressions.getOrElse(userChoice, "0")
    
    val parser = new SpelExpressionParser()
    // ok: scala-parse-expression
    val expression = parser.parseExpression(expressionText)
    val result = expression.getValue()
    Ok(s"Operation result: $result")
  }

  def good_case_5() = Action { request =>
    val userInput = request.getQueryString("name").getOrElse("")
    val sanitizedInput = ESAPI.encoder().encodeForJava(userInput)
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    context.setVariable("name", sanitizedInput)
    
    // ok: scala-parse-expression
    val expression = parser.parseExpression("'Hello, ' + #name")
    val result = expression.getValue(context)
    Ok(s"Greeting: $result")
  }

  def good_case_6() = Action { request =>
    val templateText = "'Welcome to our application'"
    val parser = new SpelExpressionParser()
    // ok: scala-parse-expression
    val expression = parser.parseExpression(templateText)
    val result = expression.getValue()
    Ok(s"Template: $result")
  }

  def good_case_7() = Action { request =>
    val userInput = request.getQueryString("value").getOrElse("")
    // Validate input is only digits
    if (!userInput.matches("^[0-9]+$")) {
      BadRequest("Invalid input")
    } else {
      val parser = new SpelExpressionParser()
      // ok: scala-parse-expression
      val expression = parser.parseExpression(userInput)
      val result = expression.getValue()
      Ok(s"Numeric value: $result")
    }
  }

  def good_case_8() = Action { request =>
    val jsonBody = request.body.asJson.getOrElse(Json.obj())
    val userValue = (jsonBody \ "value").asOpt[Int].getOrElse(0)
    
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    context.setVariable("userValue", userValue)
    
    // ok: scala-parse-expression
    val expression = parser.parseExpression("#userValue + 10")
    val result = expression.getValue(context)
    Ok(s"Calculation: $result")
  }

  def good_case_9() = Action { request =>
    val allowedOperations = Set("add", "subtract", "multiply", "divide")
    val operation = request.getQueryString("op").getOrElse("")
    
    if (!allowedOperations.contains(operation)) {
      BadRequest("Invalid operation")
    } else {
      val a = request.getQueryString("a").flatMap(s => Try(s.toInt).toOption).getOrElse(0)
      val b = request.getQueryString("b").flatMap(s => Try(s.toInt).toOption).getOrElse(0)
      
      val expressionText = operation match {
        case "add" => s"$a + $b"
        case "subtract" => s"$a - $b"
        case "multiply" => s"$a * $b"
        case "divide" => if (b != 0) s"$a / $b" else "0"
      }
      
      val parser = new SpelExpressionParser()
      // ok: scala-parse-expression
      val expression = parser.parseExpression(expressionText)
      val result = expression.getValue()
      Ok(s"Result: $result")
    }
  }

  def good_case_10() = Action { request =>
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    
    val name = ESAPI.encoder().encodeForJava(request.getQueryString("name").getOrElse(""))
    val age = Try(request.getQueryString("age").getOrElse("0").toInt).getOrElse(0)
    
    context.setVariable("name", name)
    context.setVariable("age", age)
    
    // ok: scala-parse-expression
    val expression = parser.parseExpression("'Name: ' + #name + ', Age: ' + #age")
    val result = expression.getValue(context)
    Ok(s"User info: $result")
  }

  def good_case_11() = Action { request =>
    val userInput = request.getQueryString("expr").getOrElse("")
    
    // Whitelist approach - only allow specific expressions
    val allowedExpressions = Map(
      "greeting" -> "'Hello, World!'",
      "date" -> "new java.util.Date()",
      "random" -> "T(java.lang.Math).random()"
    )
    
    val expressionText = allowedExpressions.getOrElse(userInput, "'Invalid expression'")
    val parser = new SpelExpressionParser()
    
    // ok: scala-parse-expression
    val expression = parser.parseExpression(expressionText)
    val result = expression.getValue()
    Ok(s"Result: $result")
  }

  def good_case_12() = Action { request =>
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    
    // Using constant expressions with parameterized user data
    val username = ESAPI.encoder().encodeForJava(request.getQueryString("username").getOrElse(""))
    context.setVariable("username", username)
    
    // ok: scala-parse-expression
    val expression = parser.parseExpression("'Welcome, ' + #username")
    val result = expression.getValue(context)
    Ok(s"$result")
  }

  def good_case_13() = Action { request =>
    val userInput = request.getQueryString("calculation").getOrElse("")
    
    // Validate input contains only allowed characters
    if (!userInput.matches("^[0-9+\\-*/()\\s.]+$")) {
      BadRequest("Invalid characters in expression")
    } else {
      val parser = new SpelExpressionParser()
      try {
        // ok: scala-parse-expression
        val expression = parser.parseExpression(userInput)
        val result = expression.getValue()
        Ok(s"Calculation result: $result")
      } catch {
        case e: Exception => BadRequest(s"Invalid expression: ${e.getMessage}")
      }
    }
  }

  def good_case_14() = Action { request =>
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    
    // Using a predefined template with user variables
    val template = "'Hello ' + #firstName + ' ' + #lastName + '!'"
    
    val firstName = ESAPI.encoder().encodeForJava(request.getQueryString("firstName").getOrElse(""))
    val lastName = ESAPI.encoder().encodeForJava(request.getQueryString("lastName").getOrElse(""))
    
    context.setVariable("firstName", firstName)
    context.setVariable("lastName", lastName)
    
    // ok: scala-parse-expression
    val expression = parser.parseExpression(template)
    val result = expression.getValue(context)
    Ok(s"$result")
  }

  def good_case_15() = Action { request =>
    val jsonBody = request.body.asJson.getOrElse(Json.obj())
    val config = (jsonBody \ "config").asOpt[JsObject].getOrElse(Json.obj())
    
    // Create a safe configuration object with validated values
    val safeConfig = Json.obj(
      "showHeader" -> (config \ "showHeader").asOpt[Boolean].getOrElse(true),
      "maxItems" -> (config \ "maxItems").asOpt[Int].getOrElse(10).min(100)
    )
    
    val parser = new SpelExpressionParser()
    val context = new StandardEvaluationContext()
    context.setVariable("showHeader", safeConfig("showHeader").as[Boolean])
    context.setVariable("maxItems", safeConfig("maxItems").as[Int])
    
    // ok: scala-parse-expression
    val expression = parser.parseExpression("#showHeader ? 'Showing up to ' + #maxItems + ' items' : 'Items hidden'")
    val result = expression.getValue(context)
    Ok(s"Config: $result")
  }
}