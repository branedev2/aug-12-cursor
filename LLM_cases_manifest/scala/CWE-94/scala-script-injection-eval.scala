import javax.script.{ScriptEngine, ScriptEngineManager, ScriptException}
import org.apache.commons.lang3.StringEscapeUtils
import scala.io.Source
import play.api.mvc._
import play.api.http._
import play.api.libs.json._
import scala.util.Try
import org.owasp.encoder.Encode
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
// {fact rule=autoescape-disabled@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(request: Request[AnyContent]): String = {
  val userInput = request.getQueryString("script").getOrElse("")
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  try {
    // ruleid: scala-script-injection-eval
    val result = engine.eval(s"var x = 10; $userInput; x;")
    s"Result: $result"
  } catch {
    case e: ScriptException => s"Error: ${e.getMessage}"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_2(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  val userCode = request.body.asFormUrlEncoded.get("code").head
  
  try {
    // ruleid: scala-script-injection-eval
    engine.eval(userCode)
    "Script executed successfully"
  } catch {
    case e: Exception => s"Script failed: ${e.getMessage}"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_3(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  val scriptHeader = request.headers.get("X-Custom-Script").getOrElse("")
  
  // ruleid: scala-script-injection-eval
  val result = engine.eval(s"""
    function processData(data) {
      return data * 2;
    }
    
    $scriptHeader
    
    processData(42);
  """)
  
  s"Execution result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_4(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  val jsonBody = request.body.asJson.get
  val scriptPart = (jsonBody \ "scriptCode").as[String]
  
  try {
    // ruleid: scala-script-injection-eval
    val result = engine.eval(s"function calculate() { return $scriptPart; }; calculate();")
    s"Calculation result: $result"
  } catch {
    case e: Exception => s"Calculation error: ${e.getMessage}"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_5(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  val cookie = request.cookies.get("userScript").map(_.value).getOrElse("")
  
  if (cookie.nonEmpty) {
    try {
      // ruleid: scala-script-injection-eval
      val result = engine.eval(cookie)
      s"Cookie script result: $result"
    } catch {
      case _: Exception => "Invalid script in cookie"
    }
  } else {
    "No script found in cookie"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_6(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  val scriptParts = for {
    part1 <- request.getQueryString("part1")
    part2 <- request.getQueryString("part2")
  } yield (part1, part2)
  
  scriptParts match {
    case Some((p1, p2)) =>
      val fullScript = s"$p1 + $p2"
      // ruleid: scala-script-injection-eval
      val result = engine.eval(fullScript)
      s"Combined script result: $result"
    case None =>
      "Missing script parts"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_7(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  val userAgent = request.headers.get("User-Agent").getOrElse("")
  
  // This is a contrived example but demonstrates using HTTP header as source
  if (userAgent.startsWith("CustomScript:")) {
    val script = userAgent.substring("CustomScript:".length)
    // ruleid: scala-script-injection-eval
    val result = engine.eval(script)
    s"User-Agent script result: $result"
  } else {
    "No script in User-Agent"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_8(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  val referer = request.headers.get("Referer").getOrElse("")
  
  if (referer.contains("script=")) {
    val scriptParam = referer.split("script=")(1).split("&")(0)
    // ruleid: scala-script-injection-eval
    val result = engine.eval(s"function test() { return $scriptParam; }; test();")
    s"Referer script result: $result"
  } else {
    "No script in Referer"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_9(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  val formData = request.body.asFormUrlEncoded
  val scriptTemplate = formData.flatMap(_.get("template").headOption).getOrElse("")
  val scriptValue = formData.flatMap(_.get("value").headOption).getOrElse("0")
  
  val fullScript = scriptTemplate.replace("{{value}}", scriptValue)
  
  try {
    // ruleid: scala-script-injection-eval
    val result = engine.eval(fullScript)
    s"Template evaluation result: $result"
  } catch {
    case e: Exception => s"Template error: ${e.getMessage}"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_10(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  val jsonBody = request.body.asJson.getOrElse(Json.obj())
  val operation = (jsonBody \ "operation").asOpt[String].getOrElse("")
  val operands = (jsonBody \ "operands").asOpt[Seq[Int]].getOrElse(Seq.empty)
  
  val operandsStr = operands.mkString(", ")
  val script = s"function calculate($operandsStr) { return $operation; }; calculate();"
  
  try {
    // ruleid: scala-script-injection-eval
    val result = engine.eval(script)
    s"Dynamic function result: $result"
  } catch {
    case e: Exception => s"Function error: ${e.getMessage}"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_11(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  val path = request.path
  if (path.startsWith("/eval/")) {
    val scriptPart = path.substring("/eval/".length)
    // ruleid: scala-script-injection-eval
    val result = engine.eval(s"'Path evaluation: ' + ($scriptPart)")
    result.toString
  } else {
    "Invalid path"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_12(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  for {
    json <- request.body.asJson
    rules <- (json \ "rules").asOpt[Seq[String]]
  } yield {
    val combinedRules = rules.mkString("; ")
    try {
      // ruleid: scala-script-injection-eval
      val result = engine.eval(s"""
        function applyRules() {
          $combinedRules
          return "Rules applied";
        }
        applyRules();
      """)
      result.toString
    } catch {
      case e: Exception => s"Rule error: ${e.getMessage}"
    }
  }
  
  "No rules provided"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_13(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  val expression = request.getQueryString("expr").getOrElse("1+1")
  val iterations = request.getQueryString("iterations").getOrElse("1").toInt
  
  var result: Any = null
  for (i <- 1 to iterations) {
    // ruleid: scala-script-injection-eval
    result = engine.eval(s"($expression) * $i")
  }
  
  s"Final result after $iterations iterations: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_14(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  val config = request.body.asFormUrlEncoded.getOrElse(Map.empty)
  if (config.contains("scriptConfig")) {
    val scriptConfig = config("scriptConfig").head
    
    // Attempt to parse as JSON and extract script
    try {
      val configJson = Json.parse(scriptConfig)
      val script = (configJson \ "script").as[String]
      
      // ruleid: scala-script-injection-eval
      val result = engine.eval(script)
      s"Config script result: $result"
    } catch {
      case e: Exception => s"Config error: ${e.getMessage}"
    }
  } else {
    "No script configuration provided"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_15(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  val contentType = request.headers.get("Content-Type").getOrElse("")
  if (contentType.contains("application/javascript")) {
    val scriptBody = request.body.asText.getOrElse("")
    
    // ruleid: scala-script-injection-eval
    val result = engine.eval(scriptBody)
    s"Script execution result: $result"
  } else {
    "Invalid content type"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

// True Negative Examples (Safe Code)

def good_case_1(request: Request[AnyContent]): String = {
  val userInput = request.getQueryString("script").getOrElse("")
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  // Predefined allowed operations only
  val allowedOperations = Map(
    "add" -> "function add(a, b) { return a + b; }",
    "subtract" -> "function subtract(a, b) { return a - b; }",
    "multiply" -> "function multiply(a, b) { return a * b; }"
  )
  
  if (allowedOperations.contains(userInput)) {
    // ok: scala-script-injection-eval
    val result = engine.eval(allowedOperations(userInput) + "; " + userInput + "(5, 3);")
    s"Result: $result"
  } else {
    "Invalid operation requested"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_2(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  val userInput = request.body.asFormUrlEncoded.getOrElse(Map.empty).getOrElse("input", Seq("")).head
  
  // Using bindings instead of direct script injection
  engine.put("userValue", userInput)
  
  // ok: scala-script-injection-eval
  val result = engine.eval("'The user input was: ' + userValue;")
  s"Result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_3(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  val scriptHeader = request.headers.get("X-Custom-Script").getOrElse("")
  
  // Sanitize the input using StringEscapeUtils
  val sanitizedScript = StringEscapeUtils.escapeEcmaScript(scriptHeader)
  
  // ok: scala-script-injection-eval
  val result = engine.eval(s"""
    function processData(data) {
      return 'Processed: ' + '$sanitizedScript';
    }
    
    processData(42);
  """)
  
  s"Execution result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_4(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  val jsonBody = request.body.asJson.getOrElse(Json.obj())
  
  // Extract numeric values only, no code execution
  val a = (jsonBody \ "a").asOpt[Int].getOrElse(0)
  val b = (jsonBody \ "b").asOpt[Int].getOrElse(0)
  val op = (jsonBody \ "operation").asOpt[String].getOrElse("+")
  
  // Validate operation is one of the allowed ones
  val validOp = op match {
    case "+" | "-" | "*" | "/" => op
    case _ => "+"
  }
  
  // ok: scala-script-injection-eval
  val result = engine.eval(s"$a $validOp $b")
  s"Calculation result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_5(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  val cookie = request.cookies.get("userValue").map(_.value).getOrElse("")
  
  // Sanitize and use as data, not as code
  val sanitizedValue = StringEscapeUtils.escapeEcmaScript(cookie)
  engine.put("userValue", sanitizedValue)
  
  // ok: scala-script-injection-eval
  val result = engine.eval("'The user value from cookie is: ' + userValue;")
  s"Cookie value result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_6(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  // Extract numeric values only
  val num1 = request.getQueryString("num1").flatMap(s => Try(s.toInt).toOption).getOrElse(0)
  val num2 = request.getQueryString("num2").flatMap(s => Try(s.toInt).toOption).getOrElse(0)
  
  // ok: scala-script-injection-eval
  val result = engine.eval(s"$num1 + $num2")
  s"Sum result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_7(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  val userAgent = request.headers.get("User-Agent").getOrElse("")
  
  // Just use the user agent as data, not as executable code
  engine.put("userAgent", userAgent)
  
  // ok: scala-script-injection-eval
  val result = engine.eval("'User agent: ' + userAgent;")
  s"User-Agent processing result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_8(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  // Use a whitelist of allowed expressions
  val allowedExpressions = Set("Math.PI", "Math.E", "Math.sqrt(2)", "Math.log(10)")
  val expr = request.getQueryString("expr").getOrElse("")
  
  if (allowedExpressions.contains(expr)) {
    // ok: scala-script-injection-eval
    val result = engine.eval(expr)
    s"Expression result: $result"
  } else {
    "Invalid expression"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_9(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  val formData = request.body.asFormUrlEncoded.getOrElse(Map.empty)
  val templateName = formData.getOrElse("template", Seq("default")).head
  val value = formData.getOrElse("value", Seq("0")).head.toInt
  
  // Use a predefined set of templates
  val templates = Map(
    "default" -> "function calculate(x) { return x * 2; }",
    "square" -> "function calculate(x) { return x * x; }",
    "cube" -> "function calculate(x) { return x * x * x; }"
  )
  
  val template = templates.getOrElse(templateName, templates("default"))
  
  // ok: scala-script-injection-eval
  val result = engine.eval(s"$template calculate($value);")
  s"Template calculation result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_10(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  val jsonBody = request.body.asJson.getOrElse(Json.obj())
  val operands = (jsonBody \ "operands").asOpt[Seq[Int]].getOrElse(Seq.empty)
  
  // Only allow predefined operations
  val operation = (jsonBody \ "operation").asOpt[String].getOrElse("sum") match {
    case "sum" => "operands.reduce((a, b) => a + b, 0)"
    case "product" => "operands.reduce((a, b) => a * b, 1)"
    case "average" => "operands.reduce((a, b) => a + b, 0) / operands.length"
    case _ => "operands.reduce((a, b) => a + b, 0)" // Default to sum
  }
  
  engine.put("operands", operands.toArray)
  
  // ok: scala-script-injection-eval
  val result = engine.eval(operation)
  s"Operation result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_11(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  val path = request.path
  if (path.startsWith("/calc/")) {
    // Extract only numeric values from path
    val numericPart = path.substring("/calc/".length)
    val number = Try(numericPart.toInt).getOrElse(0)
    
    // ok: scala-script-injection-eval
    val result = engine.eval(s"Math.pow($number, 2)")
    s"Square of $number is $result"
  } else {
    "Invalid path"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_12(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  case class Rule(name: String, script: String)
  
  // Predefined rules only
  val availableRules = Map(
    "double" -> Rule("double", "function apply(x) { return x * 2; }"),
    "square" -> Rule("square", "function apply(x) { return x * x; }"),
    "increment" -> Rule("increment", "function apply(x) { return x + 1; }")
  )
  
  for {
    json <- request.body.asJson
    ruleNames <- (json \ "rules").asOpt[Seq[String]]
  } yield {
    val validRules = ruleNames.filter(availableRules.contains)
    val scripts = validRules.map(name => availableRules(name).script)
    
    // ok: scala-script-injection-eval
    val result = engine.eval(scripts.mkString("\n") + "\n'Rules loaded successfully';")
    result.toString
  }
  
  "No valid rules provided"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_13(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  // Parse and validate input as numeric only
  val expression = request.getQueryString("expr").getOrElse("0")
  val iterations = request.getQueryString("iterations").flatMap(s => Try(s.toInt).toOption).getOrElse(1)
  
  // Validate expression contains only numbers and basic math operators
  val validExprPattern = "^[0-9+\\-*/().\\s]+$".r
  if (validExprPattern.matches(expression)) {
    var result: Any = null
    for (i <- 1 to iterations) {
      // ok: scala-script-injection-eval
      result = engine.eval(s"($expression) * $i")
    }
    s"Final result after $iterations iterations: $result"
  } else {
    "Invalid expression format"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_14(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  // Use a domain-specific language with limited capabilities
  case class ScriptConfig(operation: String, values: List[Int])
  
  val config = request.body.asFormUrlEncoded.getOrElse(Map.empty)
  if (config.contains("scriptConfig")) {
    try {
      val configJson = Json.parse(config("scriptConfig").head)
      val operation = (configJson \ "operation").as[String]
      val values = (configJson \ "values").as[List[Int]]
      
      val scriptConfig = ScriptConfig(operation, values)
      
      // Only allow specific operations
      val script = scriptConfig.operation match {
        case "sum" => s"${scriptConfig.values.mkString(" + ")}"
        case "product" => s"${scriptConfig.values.mkString(" * ")}"
        case "average" => s"(${scriptConfig.values.mkString(" + ")}) / ${scriptConfig.values.length}"
        case _ => "0" // Default safe value
      }
      
      // ok: scala-script-injection-eval
      val result = engine.eval(script)
      s"Config script result: $result"
    } catch {
      case e: Exception => s"Config error: ${e.getMessage}"
    }
  } else {
    "No script configuration provided"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_15(request: Request[AnyContent]): String = {
  val engine = new ScriptEngineManager().getEngineByName("nashorn")
  
  // Instead of executing user code, use a template with placeholders
  val template = """
    function calculate(a, b) {
      return a + b;
    }
    calculate(VALUE_A, VALUE_B);
  """
  
  val valueA = request.getQueryString("a").flatMap(s => Try(s.toInt).toOption).getOrElse(0)
  val valueB = request.getQueryString("b").flatMap(s => Try(s.toInt).toOption).getOrElse(0)
  
  val script = template
    .replace("VALUE_A", valueA.toString)
    .replace("VALUE_B", valueB.toString)
  
  // ok: scala-script-injection-eval
  val result = engine.eval(script)
  s"Calculation result: $result"
}
// {/fact}