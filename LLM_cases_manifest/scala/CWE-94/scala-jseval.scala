// Imports for HTTP handling and JavaScript evaluation
import play.api.mvc._
import play.api.http._
import javax.script.ScriptEngineManager
import org.owasp.encoder.Encode
import scala.concurrent.Future
import play.api.libs.json._
import scala.util.Try
import scala.util.Success
import scala.util.Failure
// {fact rule=autoescape-disabled@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(request: Request[AnyContent]): String = {
  val userInput = request.getQueryString("code").getOrElse("")
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ruleid: scala-jseval
  engine.eval(s"var result = ${userInput}; result;")
  "Executed user code"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_2(request: Request[AnyContent]): String = {
  val userInput = request.body.asFormUrlEncoded.get("script")(0)
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ruleid: scala-jseval
  val result = engine.eval(userInput).toString
  s"Result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_3(request: Request[AnyContent]): String = {
  val jsonBody = request.body.asJson.getOrElse(Json.obj())
  val scriptToRun = (jsonBody \ "scriptContent").asOpt[String].getOrElse("")
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ruleid: scala-jseval
  engine.eval(s"function calculate() { return ${scriptToRun}; }; calculate();")
  "Script executed"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_4(request: Request[AnyContent]): String = {
  val headerValue = request.headers.get("X-Custom-Script").getOrElse("")
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  try {
    // ruleid: scala-jseval
    val result = engine.eval(s"(function() { ${headerValue} })()")
    s"Executed with result: $result"
  } catch {
    case e: Exception => s"Error: ${e.getMessage}"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_5(request: Request[AnyContent]): String = {
  val cookieValue = request.cookies.get("userScript").map(_.value).getOrElse("")
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ruleid: scala-jseval
  engine.eval(cookieValue)
  "Cookie script executed"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_6(request: Request[AnyContent]): String = {
  val userInput = request.getQueryString("expression").getOrElse("2+2")
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  if (userInput.length < 100) {
    // ruleid: scala-jseval
    val result = engine.eval(userInput)
    s"Calculation result: $result"
  } else {
    "Input too long"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_7(request: Request[AnyContent]): String = {
  val params = request.queryString.map { case (k, v) => k -> v.mkString }
  val script = params.getOrElse("jsCode", "")
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ruleid: scala-jseval
  val result = engine.eval(script)
  s"Executed with result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_8(request: Request[AnyContent]): String = {
  val formData = request.body.asFormUrlEncoded
  val scriptParts = for {
    data <- formData.toList
    scriptPart <- data._2 if scriptPart.contains("function")
  } yield scriptPart
  
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ruleid: scala-jseval
  engine.eval(scriptParts.mkString("\n"))
  "Multiple script parts executed"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_9(request: Request[AnyContent]): String = {
  val jsonBody = request.body.asJson.getOrElse(Json.obj())
  val config = (jsonBody \ "config").asOpt[JsObject].getOrElse(Json.obj())
  val scriptConfig = (config \ "script").asOpt[String].getOrElse("")
  
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ruleid: scala-jseval
  engine.eval(s"var config = { script: function() { ${scriptConfig} } }; config.script();")
  "Configuration script executed"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_10(request: Request[AnyContent]): String = {
  val userAgent = request.headers.get("User-Agent").getOrElse("")
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ruleid: scala-jseval
  engine.eval(s"""
    var userAgent = "${userAgent}";
    var browserInfo = {};
    if (userAgent.indexOf("Chrome") > -1) {
      browserInfo.name = "Chrome";
    } else if (userAgent.indexOf("Firefox") > -1) {
      browserInfo.name = "Firefox";
    } else {
      browserInfo.name = "Unknown";
    }
    browserInfo;
  """)
  "Browser detected"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_11(request: Request[AnyContent]): String = {
  val referer = request.headers.get("Referer").getOrElse("")
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  try {
    // ruleid: scala-jseval
    val result = engine.eval(s"""
      function processReferer(ref) {
        return ref.split('/')[2];
      }
      processReferer("${referer}");
    """)
    s"Processed referer: $result"
  } catch {
    case e: Exception => "Error processing referer"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_12(request: Request[AnyContent]): String = {
  val pathSegments = request.path.split("/")
  val lastSegment = if (pathSegments.nonEmpty) pathSegments.last else ""
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ruleid: scala-jseval
  val result = engine.eval(s"'${lastSegment}'.toUpperCase()")
  s"Processed path: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_13(request: Request[AnyContent]): String = {
  val queryParams = request.queryString.map { case (k, v) => s"$k=${v.mkString}" }.mkString("&")
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ruleid: scala-jseval
  engine.eval(s"""
    var params = "${queryParams}";
    var paramCount = params.split('&').length;
    "Found " + paramCount + " parameters";
  """)
  "Query parameters processed"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_14(request: Request[AnyContent]): String = {
  val jsonBody = request.body.asJson.getOrElse(Json.obj())
  val rules = (jsonBody \ "validationRules").asOpt[String].getOrElse("")
  val data = (jsonBody \ "data").asOpt[String].getOrElse("{}")
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ruleid: scala-jseval
  val result = engine.eval(s"""
    var data = $data;
    var validationFunction = function(d) {
      $rules
      return true;
    };
    validationFunction(data);
  """)
  s"Validation result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

def bad_case_15(request: Request[AnyContent]): String = {
  val contentType = request.headers.get("Content-Type").getOrElse("")
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ruleid: scala-jseval
  engine.eval(s"""
    var contentType = "${contentType}";
    var isJson = contentType.indexOf("application/json") > -1;
    var isForm = contentType.indexOf("form-urlencoded") > -1;
    var isMultipart = contentType.indexOf("multipart/form-data") > -1;
    "Content type is " + (isJson ? "JSON" : isForm ? "Form" : isMultipart ? "Multipart" : "Other");
  """)
  "Content type processed"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

// True Negative Examples (Safe Code)

def good_case_1(request: Request[AnyContent]): String = {
  val userInput = request.getQueryString("code").getOrElse("")
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  // ok: scala-jseval
  val sanitizedInput = Encode.forJavaScript(userInput)
  engine.eval(s"var result = '${sanitizedInput}'; result;")
  "Executed user code safely"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_2(request: Request[AnyContent]): String = {
  val userInput = request.body.asFormUrlEncoded.get("script")(0)
  // ok: scala-jseval
  // Instead of eval, use a safer alternative like a predefined function
  val result = if (userInput == "add") {
    2 + 2
  } else if (userInput == "multiply") {
    2 * 2
  } else {
    0
  }
  s"Result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_3(request: Request[AnyContent]): String = {
  val jsonBody = request.body.asJson.getOrElse(Json.obj())
  val operation = (jsonBody \ "operation").asOpt[String].getOrElse("")
  val a = (jsonBody \ "a").asOpt[Int].getOrElse(0)
  val b = (jsonBody \ "b").asOpt[Int].getOrElse(0)
  
  // ok: scala-jseval
  // Using pattern matching instead of eval
  val result = operation match {
    case "add" => a + b
    case "subtract" => a - b
    case "multiply" => a * b
    case "divide" if b != 0 => a / b
    case _ => 0
  }
  s"Result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_4(request: Request[AnyContent]): String = {
  val headerValue = request.headers.get("X-Custom-Script").getOrElse("")
  // ok: scala-jseval
  // Using a whitelist of allowed expressions
  val allowedExpressions = Set("2+2", "3*4", "10-5")
  val result = if (allowedExpressions.contains(headerValue)) {
    headerValue match {
      case "2+2" => 4
      case "3*4" => 12
      case "10-5" => 5
      case _ => 0
    }
  } else {
    0
  }
  s"Result: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_5(request: Request[AnyContent]): String = {
  val cookieValue = request.cookies.get("userScript").map(_.value).getOrElse("")
  // ok: scala-jseval
  // Parse JSON instead of evaluating as code
  Try(Json.parse(cookieValue)) match {
    case Success(json) => s"Parsed JSON: ${json.toString}"
    case Failure(_) => "Invalid JSON"
  }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_6(request: Request[AnyContent]): String = {
  val expression = request.getQueryString("expression").getOrElse("")
  // ok: scala-jseval
  // Use a simple calculator instead of eval
  val calculator = new SimpleCalculator()
  val result = calculator.calculate(expression)
  s"Calculation result: $result"
}
// {/fact}

class SimpleCalculator {
  def calculate(expr: String): Double = {
    // A simple calculator that only handles basic operations
    val tokens = expr.replaceAll("\\s", "").split("(?<=[-+*/])|(?=[-+*/])")
    if (tokens.length != 3) return 0
    
    try {
      val a = tokens(0).toDouble
      val op = tokens(1)
      val b = tokens(2).toDouble
      
      op match {
        case "+" => a + b
        case "-" => a - b
        case "*" => a * b
        case "/" if b != 0 => a / b
        case _ => 0
      }
    } catch {
      case _: Exception => 0
    }
  }
}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_7(request: Request[AnyContent]): String = {
  val params = request.queryString.map { case (k, v) => k -> v.mkString }
  val jsCode = params.getOrElse("jsCode", "")
  
  // ok: scala-jseval
  // Instead of evaluating user code, use a template with fixed logic
  val template = """
    function processData(data) {
      return data.toUpperCase();
    }
    processData('%s');
  """
  val sanitizedInput = Encode.forJavaScript(jsCode)
  val engine = new ScriptEngineManager().getEngineByName("JavaScript")
  val result = engine.eval(String.format(template, sanitizedInput))
  s"Processed: $result"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_8(request: Request[AnyContent]): String = {
  val formData = request.body.asFormUrlEncoded
  val scriptParts = for {
    data <- formData.toList
    scriptPart <- data._2 if scriptPart.contains("function")
  } yield scriptPart
  
  // ok: scala-jseval
  // Instead of evaluating, just count and report
  val count = scriptParts.size
  s"Found $count script parts (not executed for security)"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_9(request: Request[AnyContent]): String = {
  val jsonBody = request.body.asJson.getOrElse(Json.obj())
  val config = (jsonBody \ "config").asOpt[JsObject].getOrElse(Json.obj())
  
  // ok: scala-jseval
  // Process the configuration as data, not code
  val processedConfig = config.fields.map { case (key, value) =>
    s"$key: ${value.toString}"
  }.mkString("\n")
  
  s"Processed configuration:\n$processedConfig"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_10(request: Request[AnyContent]): String = {
  val userAgent = request.headers.get("User-Agent").getOrElse("")
  
  // ok: scala-jseval
  // Direct string processing instead of eval
  val browserInfo = if (userAgent.contains("Chrome")) {
    "Chrome"
  } else if (userAgent.contains("Firefox")) {
    "Firefox"
  } else {
    "Unknown"
  }
  
  s"Browser detected: $browserInfo"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_11(request: Request[AnyContent]): String = {
  val referer = request.headers.get("Referer").getOrElse("")
  
  // ok: scala-jseval
  // Process the referer directly in Scala
  val domain = Try {
    val parts = referer.split("/")
    if (parts.length >= 3) parts(2) else "unknown"
  }.getOrElse("unknown")
  
  s"Processed referer: $domain"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_12(request: Request[AnyContent]): String = {
  val pathSegments = request.path.split("/")
  val lastSegment = if (pathSegments.nonEmpty) pathSegments.last else ""
  
  // ok: scala-jseval
  // Process directly in Scala
  val processed = lastSegment.toUpperCase
  s"Processed path: $processed"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_13(request: Request[AnyContent]): String = {
  val queryParams = request.queryString
  
  // ok: scala-jseval
  // Process directly in Scala
  val paramCount = queryParams.size
  s"Found $paramCount parameters"
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_14(request: Request[AnyContent]): String = {
  val jsonBody = request.body.asJson.getOrElse(Json.obj())
  val data = (jsonBody \ "data").asOpt[JsObject].getOrElse(Json.obj())
  
  // ok: scala-jseval
  // Use a predefined validation function instead of evaluating code
  val isValid = validateData(data)
  s"Validation result: $isValid"
}
// {/fact}

def validateData(data: JsObject): Boolean = {
  // A simple validation function
  val requiredFields = Set("name", "email")
  val hasAllRequired = requiredFields.forall(field => (data \ field).isDefined)
  val email = (data \ "email").asOpt[String].getOrElse("")
  val validEmail = email.contains("@") && email.contains(".")
  
  hasAllRequired && validEmail
}
// {fact rule=autoescape-disabled@v1.0 defects=0}

def good_case_15(request: Request[AnyContent]): String = {
  val contentType = request.headers.get("Content-Type").getOrElse("")
  
  // ok: scala-jseval
  // Process directly in Scala
  val contentTypeInfo = if (contentType.contains("application/json")) {
    "JSON"
  } else if (contentType.contains("form-urlencoded")) {
    "Form"
  } else if (contentType.contains("multipart/form-data")) {
    "Multipart"
  } else {
    "Other"
  }
  
  s"Content type is $contentTypeInfo"
}
// {/fact}