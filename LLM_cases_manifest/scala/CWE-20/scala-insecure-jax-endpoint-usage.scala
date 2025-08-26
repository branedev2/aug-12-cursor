// Imports for JAX-RS/JAX-WS
import javax.ws.rs._
import javax.ws.rs.core._
import javax.xml.ws._
import javax.jws._
import java.util.List
import java.util.ArrayList
import javax.xml.bind.annotation._
import org.owasp.encoder.Encode
import org.apache.commons.lang3.StringEscapeUtils
import java.util.regex.Pattern
import javax.validation.constraints._
import javax.validation.Valid
import org.hibernate.validator.constraints.SafeHtml
import scala.collection.JavaConverters._
import scala.collection.mutable.ArrayBuffer

// True Positive Examples (Vulnerable Code)

@Path("/users")
class bad_case_1 {
  @GET
  @Path("/{id}")
  @Produces(Array("text/html"))
  def getUser(@PathParam("id") id: String): Response = {
    // ruleid: scala-insecure-jax-endpoint-usage
    val html = s"<div>User ID: $id</div>"
    Response.ok(html).build()
  }
}

@Path("/search")
class bad_case_2 {
  @POST
  @Consumes(Array(MediaType.APPLICATION_FORM_URLENCODED))
  @Produces(Array(MediaType.TEXT_HTML))
  def search(@FormParam("query") query: String): String = {
    // ruleid: scala-insecure-jax-endpoint-usage
    s"<h1>Search Results for: $query</h1><div>Results will appear here</div>"
  }
}

@Path("/comments")
class bad_case_3 {
  @POST
  @Consumes(Array(MediaType.APPLICATION_JSON))
  @Produces(Array(MediaType.TEXT_HTML))
  def addComment(comment: CommentDTO): Response = {
    // ruleid: scala-insecure-jax-endpoint-usage
    val html = s"<div class='comment'>New comment added: ${comment.text}</div>"
    Response.ok(html).build()
  }
}

@WebService
class bad_case_4 {
  @WebMethod
  def processOrder(@WebParam(name = "orderId") orderId: String): String = {
    // Database query without validation
    // ruleid: scala-insecure-jax-endpoint-usage
    val query = s"SELECT * FROM orders WHERE id = $orderId"
    // Execute query and process results
    s"Order $orderId processed successfully"
  }
}

@Path("/products")
class bad_case_5 {
  @GET
  @Produces(Array(MediaType.APPLICATION_JSON))
  def getProducts(@QueryParam("category") category: String): Response = {
    // ruleid: scala-insecure-jax-endpoint-usage
    val sql = s"SELECT * FROM products WHERE category = '$category'"
    // Execute SQL and return results
    Response.ok("{}").build()
  }
}

@Path("/scripts")
class bad_case_6 {
  @GET
  @Produces(Array("application/javascript"))
  def getScript(@QueryParam("name") name: String): Response = {
    // ruleid: scala-insecure-jax-endpoint-usage
    val script = s"function initialize() { console.log('Loading script: $name'); }"
    Response.ok(script).build()
  }
}

@Path("/profile")
class bad_case_7 {
  @PUT
  @Consumes(Array(MediaType.APPLICATION_JSON))
  def updateProfile(profile: ProfileDTO): Response = {
    // ruleid: scala-insecure-jax-endpoint-usage
    val sql = s"UPDATE users SET bio = '${profile.bio}', website = '${profile.website}' WHERE id = ${profile.id}"
    // Execute SQL
    Response.ok().build()
  }
}

@WebService
class bad_case_8 {
  @WebMethod
  def generateReport(@WebParam(name = "template") template: String, 
                    @WebParam(name = "data") data: String): String = {
    // ruleid: scala-insecure-jax-endpoint-usage
    s"<html><body><h1>$template</h1><div>$data</div></body></html>"
  }
}

@Path("/redirect")
class bad_case_9 {
  @GET
  def redirect(@QueryParam("url") url: String): Response = {
    // ruleid: scala-insecure-jax-endpoint-usage
    Response.temporaryRedirect(new java.net.URI(url)).build()
  }
}

@Path("/files")
class bad_case_10 {
  @GET
  @Path("/{filename}")
  @Produces(Array(MediaType.APPLICATION_OCTET_STREAM))
  def getFile(@PathParam("filename") filename: String): Response = {
    // ruleid: scala-insecure-jax-endpoint-usage
    val file = new java.io.File(s"/data/files/$filename")
    Response.ok(file).build()
  }
}

@Path("/execute")
class bad_case_11 {
  @POST
  @Consumes(Array(MediaType.APPLICATION_FORM_URLENCODED))
  def executeCommand(@FormParam("cmd") cmd: String): Response = {
    // ruleid: scala-insecure-jax-endpoint-usage
    val process = Runtime.getRuntime.exec(cmd)
    Response.ok().build()
  }
}

@WebService
class bad_case_12 {
  @WebMethod
  def processXml(@WebParam(name = "xml") xml: String): String = {
    // ruleid: scala-insecure-jax-endpoint-usage
    val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new java.io.ByteArrayInputStream(xml.getBytes()))
    // Process XML without validation
    "XML processed"
  }
}

@Path("/eval")
class bad_case_13 {
  @GET
  def evaluate(@QueryParam("expression") expression: String): Response = {
    // ruleid: scala-insecure-jax-endpoint-usage
    val engine = new javax.script.ScriptEngineManager().getEngineByName("JavaScript")
    val result = engine.eval(expression)
    Response.ok(result.toString).build()
  }
}

@Path("/messages")
class bad_case_14 {
  @POST
  @Consumes(Array(MediaType.APPLICATION_JSON))
  @Produces(Array(MediaType.TEXT_HTML))
  def postMessage(message: MessageDTO): Response = {
    // ruleid: scala-insecure-jax-endpoint-usage
    val html = s"<div class='message'>${message.sender}: ${message.content}</div>"
    Response.ok(html).build()
  }
}

@WebService
class bad_case_15 {
  @WebMethod
  def createUser(@WebParam(name = "username") username: String, 
                @WebParam(name = "role") role: String): String = {
    // ruleid: scala-insecure-jax-endpoint-usage
    val sql = s"INSERT INTO users (username, role) VALUES ('$username', '$role')"
    // Execute SQL
    s"User $username created with role $role"
  }
}

// True Negative Examples (Secure Code)

@Path("/users")
class good_case_1 {
  @GET
  @Path("/{id}")
  @Produces(Array("text/html"))
  def getUser(@PathParam("id") id: String): Response = {
    // ok: scala-insecure-jax-endpoint-usage
    val sanitizedId = Encode.forHtml(id)
    val html = s"<div>User ID: $sanitizedId</div>"
    Response.ok(html).build()
  }
}

@Path("/search")
class good_case_2 {
  @POST
  @Consumes(Array(MediaType.APPLICATION_FORM_URLENCODED))
  @Produces(Array(MediaType.TEXT_HTML))
  def search(@FormParam("query") query: String): String = {
    // ok: scala-insecure-jax-endpoint-usage
    val sanitizedQuery = Encode.forHtml(query)
    s"<h1>Search Results for: $sanitizedQuery</h1><div>Results will appear here</div>"
  }
}

@Path("/comments")
class good_case_3 {
  @POST
  @Consumes(Array(MediaType.APPLICATION_JSON))
  @Produces(Array(MediaType.TEXT_HTML))
  def addComment(@Valid comment: CommentDTO): Response = {
    // ok: scala-insecure-jax-endpoint-usage
    val sanitizedText = Encode.forHtml(comment.text)
    val html = s"<div class='comment'>New comment added: $sanitizedText</div>"
    Response.ok(html).build()
  }
}

@WebService
class good_case_4 {
  @WebMethod
  def processOrder(@WebParam(name = "orderId") orderId: String): String = {
    // Validate input
    // ok: scala-insecure-jax-endpoint-usage
    if (!orderId.matches("\\d+")) {
      throw new IllegalArgumentException("Invalid order ID format")
    }
    val query = "SELECT * FROM orders WHERE id = ?"
    // Use prepared statement with parameter binding
    s"Order $orderId processed successfully"
  }
}

@Path("/products")
class good_case_5 {
  @GET
  @Produces(Array(MediaType.APPLICATION_JSON))
  def getProducts(@QueryParam("category") category: String): Response = {
    // ok: scala-insecure-jax-endpoint-usage
    val validCategories = List("electronics", "books", "clothing")
    if (!validCategories.contains(category)) {
      return Response.status(Response.Status.BAD_REQUEST).build()
    }
    val sql = "SELECT * FROM products WHERE category = ?"
    // Execute SQL with prepared statement
    Response.ok("{}").build()
  }
}

@Path("/scripts")
class good_case_6 {
  @GET
  @Produces(Array("application/javascript"))
  def getScript(@QueryParam("name") @Pattern(regexp = "[a-zA-Z0-9_]+") name: String): Response = {
    // ok: scala-insecure-jax-endpoint-usage
    val safeScriptName = name.replaceAll("[^a-zA-Z0-9_]", "")
    val script = s"function initialize() { console.log('Loading script: $safeScriptName'); }"
    Response.ok(script).build()
  }
}

@Path("/profile")
class good_case_7 {
  @PUT
  @Consumes(Array(MediaType.APPLICATION_JSON))
  def updateProfile(@Valid profile: ProfileDTO): Response = {
    // ok: scala-insecure-jax-endpoint-usage
    // Using prepared statements with parameter binding
    val sql = "UPDATE users SET bio = ?, website = ? WHERE id = ?"
    // Execute SQL with prepared statement
    Response.ok().build()
  }
}

@WebService
class good_case_8 {
  @WebMethod
  def generateReport(@WebParam(name = "template") template: String, 
                    @WebParam(name = "data") data: String): String = {
    // ok: scala-insecure-jax-endpoint-usage
    val safeTemplate = Encode.forHtml(template)
    val safeData = Encode.forHtml(data)
    s"<html><body><h1>$safeTemplate</h1><div>$safeData</div></body></html>"
  }
}

@Path("/redirect")
class good_case_9 {
  @GET
  def redirect(@QueryParam("url") url: String): Response = {
    // ok: scala-insecure-jax-endpoint-usage
    val allowedDomains = List("example.com", "trusted-site.org")
    val uri = new java.net.URI(url)
    if (!allowedDomains.exists(domain => uri.getHost.endsWith(domain))) {
      return Response.status(Response.Status.BAD_REQUEST).build()
    }
    Response.temporaryRedirect(uri).build()
  }
}

@Path("/files")
class good_case_10 {
  @GET
  @Path("/{filename}")
  @Produces(Array(MediaType.APPLICATION_OCTET_STREAM))
  def getFile(@PathParam("filename") filename: String): Response = {
    // ok: scala-insecure-jax-endpoint-usage
    if (filename.contains("..") || filename.contains("/")) {
      return Response.status(Response.Status.BAD_REQUEST).build()
    }
    val safeFilename = filename.replaceAll("[^a-zA-Z0-9._-]", "")
    val file = new java.io.File(s"/data/files/$safeFilename")
    Response.ok(file).build()
  }
}

@Path("/execute")
class good_case_11 {
  @POST
  @Consumes(Array(MediaType.APPLICATION_FORM_URLENCODED))
  def executeCommand(@FormParam("cmd") cmd: String): Response = {
    // ok: scala-insecure-jax-endpoint-usage
    val allowedCommands = Map(
      "status" -> "systemctl status application",
      "version" -> "cat /opt/app/version.txt"
    )
    
    if (!allowedCommands.contains(cmd)) {
      return Response.status(Response.Status.BAD_REQUEST).build()
    }
    
    val process = Runtime.getRuntime.exec(allowedCommands(cmd))
    Response.ok().build()
  }
}

@WebService
class good_case_12 {
  @WebMethod
  def processXml(@WebParam(name = "xml") xml: String): String = {
    // ok: scala-insecure-jax-endpoint-usage
    val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
    // Prevent XXE attacks
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new java.io.ByteArrayInputStream(xml.getBytes()))
    "XML processed securely"
  }
}

@Path("/eval")
class good_case_13 {
  @GET
  def evaluate(@QueryParam("operation") operation: String, 
               @QueryParam("a") @Min(0) @Max(1000) a: Int, 
               @QueryParam("b") @Min(0) @Max(1000) b: Int): Response = {
    // ok: scala-insecure-jax-endpoint-usage
    val result = operation match {
      case "add" => a + b
      case "subtract" => a - b
      case "multiply" => a * b
      case "divide" if b != 0 => a / b
      case _ => throw new IllegalArgumentException("Invalid operation")
    }
    Response.ok(result.toString).build()
  }
}

@Path("/messages")
class good_case_14 {
  @POST
  @Consumes(Array(MediaType.APPLICATION_JSON))
  @Produces(Array(MediaType.TEXT_HTML))
  def postMessage(@Valid message: MessageDTO): Response = {
    // ok: scala-insecure-jax-endpoint-usage
    val sanitizedSender = Encode.forHtml(message.sender)
    val sanitizedContent = Encode.forHtml(message.content)
    val html = s"<div class='message'>$sanitizedSender: $sanitizedContent</div>"
    Response.ok(html).build()
  }
}

@WebService
class good_case_15 {
  @WebMethod
  def createUser(@WebParam(name = "username") @Pattern(regexp = "[a-zA-Z0-9_]+") username: String, 
                @WebParam(name = "role") role: String): String = {
    // ok: scala-insecure-jax-endpoint-usage
    val validRoles = List("user", "editor", "admin")
    if (!validRoles.contains(role)) {
      throw new IllegalArgumentException("Invalid role specified")
    }
    
    // Using prepared statement
    val sql = "INSERT INTO users (username, role) VALUES (?, ?)"
    // Execute SQL with prepared statement
    s"User $username created with role $role"
  }
}

// Data Transfer Objects
case class CommentDTO(@SafeHtml var text: String)
case class ProfileDTO(var id: Long, @SafeHtml var bio: String, @Pattern(regexp = "https?://.+") var website: String)
case class MessageDTO(@Pattern(regexp = "[a-zA-Z0-9_]+") var sender: String, @SafeHtml var content: String)