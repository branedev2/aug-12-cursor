import scala.sys.process._
import scala.io.Source
import play.api.mvc._
import play.api.http._
import play.api.libs.json._
import com.google.common.html.HtmlEscapers
import javax.inject._
import java.io.File
import scala.util.Try
import scala.util.Success
import scala.util.Failure
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.HttpRequest
import akka.http.scaladsl.server.Route
import org.apache.commons.lang3.StringEscapeUtils
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global

// True Positive Examples (Vulnerable Code)

class VulnerableCommandController @Inject()(cc: ControllerComponents) extends AbstractController(cc) {
  
  // Example 1: Direct command execution with user input
  def bad_case_1() = Action { request =>
    val filename = request.getQueryString("filename").getOrElse("default.txt")
    // ruleid: scala-os-command-injection
    val result = s"ls -la $filename".!!
    Ok(s"Command result: $result")
  }
  
  // Example 2: Using Process with user input
  def bad_case_2() = Action { request =>
    val command = request.getQueryString("cmd").getOrElse("echo hello")
    // ruleid: scala-os-command-injection
    val output = Process(command).!!
    Ok(s"Executed: $output")
  }
  
  // Example 3: Using array form but still vulnerable
  def bad_case_3() = Action { request =>
    val searchTerm = request.getQueryString("search").getOrElse("")
    // ruleid: scala-os-command-injection
    val result = Process(Seq("grep", searchTerm, "/var/log/system.log")).!!
    Ok(s"Search results: $result")
  }
  
  // Example 4: Using string interpolation in a more complex command
  def bad_case_4() = Action { request =>
    val username = request.getQueryString("username").getOrElse("guest")
    val directory = request.getQueryString("dir").getOrElse("/tmp")
    // ruleid: scala-os-command-injection
    val output = s"find $directory -user $username -type f -name '*.log'".!!
    Ok(s"Files found: $output")
  }
  
  // Example 5: Using POST data
  def bad_case_5() = Action(parse.form(Forms.single("command" -> Forms.text))) { request =>
    val command = request.body.get("command").getOrElse("echo 'No command'")
    // ruleid: scala-os-command-injection
    val output = Process(command).!!
    Ok(s"Command output: $output")
  }
}

// More vulnerable examples using different frameworks and patterns

// Example 6: Using Akka HTTP
object BadAkkaExample {
  val bad_case_6: Route = path("execute") {
    get {
      parameter("cmd") { cmd =>
        // ruleid: scala-os-command-injection
        val result = s"$cmd".!!
        complete(s"Result: $result")
      }
    }
  }
}

// Example 7: Using ProcessBuilder with user input
class CommandService {
  def bad_case_7(request: HttpRequest): String = {
    val command = request.uri.query().get("command").getOrElse("echo 'No command'")
    // ruleid: scala-os-command-injection
    val processBuilder = Process(command)
    processBuilder.!!
  }
}
// {fact rule=os-command-injection@v1.0 defects=1}

// Example 8: Using header value for command
def bad_case_8() = Action { request =>
  val userAgent = request.headers.get("User-Agent").getOrElse("unknown")
  // ruleid: scala-os-command-injection
  val output = s"echo $userAgent > /tmp/user_agents.log".!!
  Ok("User agent logged")
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

// Example 9: Using JSON body for command
def bad_case_9() = Action(parse.json) { request =>
  val command = (request.body \ "command").as[String]
  // ruleid: scala-os-command-injection
  val result = Process(command).!!
  Ok(Json.obj("result" -> result))
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

// Example 10: Using cookie value in command
def bad_case_10() = Action { request =>
  val sessionId = request.cookies.get("sessionId").map(_.value).getOrElse("unknown")
  // ruleid: scala-os-command-injection
  val result = s"grep $sessionId /var/log/sessions.log".!!
  Ok(s"Session info: $result")
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

// Example 11: Command injection with string concatenation
def bad_case_11() = Action { request =>
  val filename = request.getQueryString("file").getOrElse("default.txt")
  // ruleid: scala-os-command-injection
  val output = ("cat " + filename).!!
  Ok(s"File contents: $output")
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

// Example 12: Using form data with multiple parameters
def bad_case_12() = Action(parse.formUrlEncoded) { request =>
  val user = request.body.get("user").flatMap(_.headOption).getOrElse("nobody")
  val action = request.body.get("action").flatMap(_.headOption).getOrElse("list")
  // ruleid: scala-os-command-injection
  val result = s"$action -l $user".!!
  Ok(s"Command result: $result")
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

// Example 13: Using path parameters
def bad_case_13(username: String) = Action { request =>
  // ruleid: scala-os-command-injection
  val output = s"id $username".!!
  Ok(s"User info: $output")
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

// Example 14: Using multiple inputs in a complex command
def bad_case_14() = Action { request =>
  val filename = request.getQueryString("file").getOrElse("data.txt")
  val pattern = request.getQueryString("pattern").getOrElse(".*")
  val lines = request.getQueryString("lines").getOrElse("10")
  // ruleid: scala-os-command-injection
  val result = s"grep '$pattern' $filename | head -n $lines".!!
  Ok(s"Search results: $result")
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

// Example 15: Using a list of commands from user input
def bad_case_15() = Action(parse.json) { request =>
  val commands = (request.body \ "commands").as[List[String]]
  val commandString = commands.mkString(" && ")
  // ruleid: scala-os-command-injection
  val output = Process(commandString).!!
  Ok(s"Commands executed: $output")
}
// {/fact}

// True Negative Examples (Safe Code)

class SafeCommandController @Inject()(cc: ControllerComponents) extends AbstractController(cc) {
  
  // Example 1: Using HtmlEscapers to sanitize input
  def good_case_1() = Action { request =>
    val filename = request.getQueryString("filename").getOrElse("default.txt")
    // ok: scala-os-command-injection
    val sanitizedFilename = HtmlEscapers.htmlEscaper().escape(filename)
    val result = s"ls -la $sanitizedFilename".!!
    Ok(s"Command result: $result")
  }
  
  // Example 2: Using a whitelist of allowed commands
  def good_case_2() = Action { request =>
    val commandOption = request.getQueryString("cmd").getOrElse("list")
    val allowedCommands = Map(
      "list" -> "ls -la",
      "disk" -> "df -h",
      "memory" -> "free -m"
    )
    // ok: scala-os-command-injection
    val safeCommand = allowedCommands.getOrElse(commandOption, "echo 'Invalid command'")
    val output = Process(safeCommand).!!
    Ok(s"Executed: $output")
  }
  
  // Example 3: Using array form with sanitized input
  def good_case_3() = Action { request =>
    val searchTerm = request.getQueryString("search").getOrElse("")
    // ok: scala-os-command-injection
    val sanitizedTerm = HtmlEscapers.htmlEscaper().escape(searchTerm)
    val result = Process(Seq("grep", sanitizedTerm, "/var/log/system.log")).!!
    Ok(s"Search results: $result")
  }
  
  // Example 4: Using fixed commands with no user input
  def good_case_4() = Action { request =>
    // ok: scala-os-command-injection
    val output = "ls -la /tmp".!!
    Ok(s"Files in /tmp: $output")
  }
  
  // Example 5: Validating input against a pattern
  def good_case_5() = Action { request =>
    val filename = request.getQueryString("filename").getOrElse("default.txt")
    if (!filename.matches("[a-zA-Z0-9_.-]+")) {
      BadRequest("Invalid filename")
    } else {
      // ok: scala-os-command-injection
      val result = s"cat /safe/directory/$filename".!!
      Ok(s"File contents: $result")
    }
  }
}

// More safe examples using different frameworks and patterns

// Example 6: Using Akka HTTP with sanitization
object SafeAkkaExample {
  val good_case_6: Route = path("execute") {
    get {
      parameter("cmd") { cmd =>
        // ok: scala-os-command-injection
        val sanitizedCmd = HtmlEscapers.htmlEscaper().escape(cmd)
        val result = s"echo $sanitizedCmd".!!
        complete(s"Result: $result")
      }
    }
  }
}

// Example 7: Using a dedicated function for command execution
class SafeCommandService {
  private val allowedCommands = Set("list", "status", "version")
  
  def good_case_7(request: HttpRequest): String = {
    val command = request.uri.query().get("command").getOrElse("list")
    // ok: scala-os-command-injection
    if (allowedCommands.contains(command)) {
      val actualCommand = command match {
        case "list" => "ls -la"
        case "status" => "systemctl status apache2"
        case "version" => "cat /etc/os-release"
      }
      Process(actualCommand).!!
    } else {
      "Invalid command"
    }
  }
}
// {fact rule=os-command-injection@v1.0 defects=0}

// Example 8: Using Apache Commons StringEscapeUtils
def good_case_8() = Action { request =>
  val userAgent = request.headers.get("User-Agent").getOrElse("unknown")
  // ok: scala-os-command-injection
  val sanitizedAgent = StringEscapeUtils.escapeJava(userAgent)
  val output = s"echo $sanitizedAgent > /tmp/user_agents.log".!!
  Ok("User agent logged")
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

// Example 9: Using predefined commands with parameters
def good_case_9() = Action(parse.json) { request =>
  val action = (request.body \ "action").as[String]
  val filename = (request.body \ "filename").as[String]
  
  // ok: scala-os-command-injection
  val sanitizedFilename = HtmlEscapers.htmlEscaper().escape(filename)
  val command = action match {
    case "read" => s"cat /safe/directory/$sanitizedFilename"
    case "count" => s"wc -l /safe/directory/$sanitizedFilename"
    case _ => "echo 'Invalid action'"
  }
  
  val result = Process(command).!!
  Ok(Json.obj("result" -> result))
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

// Example 10: Using Java's ProcessBuilder for safer execution
def good_case_10() = Action { request =>
  val filename = request.getQueryString("file").getOrElse("data.txt")
  // ok: scala-os-command-injection
  val sanitizedFilename = HtmlEscapers.htmlEscaper().escape(filename)
  val processBuilder = new ProcessBuilder("cat", s"/safe/directory/$sanitizedFilename")
  val process = processBuilder.start()
  val output = Source.fromInputStream(process.getInputStream).mkString
  Ok(s"File contents: $output")
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

// Example 11: Using Try to handle errors and sanitize input
def good_case_11() = Action { request =>
  val command = request.getQueryString("cmd").getOrElse("echo hello")
  // ok: scala-os-command-injection
  val sanitizedCommand = HtmlEscapers.htmlEscaper().escape(command)
  val result = Try(s"echo $sanitizedCommand".!!) match {
    case Success(output) => output
    case Failure(e) => s"Error: ${e.getMessage}"
  }
  Ok(s"Command output: $result")
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

// Example 12: Using a custom validation function
def good_case_12() = Action { request =>
  def isValidFilename(name: String): Boolean = {
    name.matches("[a-zA-Z0-9_.-]+") && !name.contains("..")
  }
  
  val filename = request.getQueryString("file").getOrElse("default.txt")
  if (isValidFilename(filename)) {
    // ok: scala-os-command-injection
    val result = s"ls -la /safe/directory/$filename".!!
    Ok(s"File info: $result")
  } else {
    BadRequest("Invalid filename")
  }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

// Example 13: Using Future for async execution with sanitization
def good_case_13() = Action.async { request =>
  val input = request.getQueryString("input").getOrElse("")
  // ok: scala-os-command-injection
  val sanitizedInput = HtmlEscapers.htmlEscaper().escape(input)
  val futureResult = Future {
    s"echo $sanitizedInput".!!
  }
  
  futureResult.map { result =>
    Ok(s"Result: $result")
  }.recover {
    case e => InternalServerError(s"Error: ${e.getMessage}")
  }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

// Example 14: Using a combination of validation techniques
def good_case_14() = Action { request =>
  val filename = request.getQueryString("file").getOrElse("")
  val sanitizedFilename = HtmlEscapers.htmlEscaper().escape(filename)
  
  if (sanitizedFilename.isEmpty || sanitizedFilename.contains("..")) {
    BadRequest("Invalid filename")
  } else {
    val file = new File(s"/safe/directory/$sanitizedFilename")
    if (!file.exists() || !file.isFile) {
      NotFound("File not found")
    } else {
      // ok: scala-os-command-injection
      val output = s"cat ${file.getAbsolutePath}".!!
      Ok(s"File contents: $output")
    }
  }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

// Example 15: Using a safe wrapper function for command execution
def good_case_15() = Action { request =>
  def executeCommand(cmd: String, args: String*): String = {
    val sanitizedArgs = args.map(HtmlEscapers.htmlEscaper().escape)
    Process(Seq(cmd) ++ sanitizedArgs).!!
  }
  
  val searchTerm = request.getQueryString("term").getOrElse("")
  // ok: scala-os-command-injection
  val result = executeCommand("grep", searchTerm, "/var/log/safe.log")
  Ok(s"Search results: $result")
}
// {/fact}