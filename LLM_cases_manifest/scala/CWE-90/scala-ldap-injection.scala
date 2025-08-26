import javax.naming.directory._
import javax.naming._
import javax.servlet.http._
import javax.servlet._
import play.api.mvc._
import play.api.http._
import play.api.libs.json._
import scala.util.Try
import org.apache.commons.text.StringEscapeUtils
import scala.collection.JavaConverters._
import org.springframework.web.bind.annotation._
import org.springframework.stereotype.Controller
import org.springframework.http.ResponseEntity
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.HttpResponse
import akka.http.scaladsl.server.Route

// True Positive Examples (Vulnerable Code)

// Example 1: Basic LDAP injection in a servlet
class bad_case_1 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val username = request.getParameter("username")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = s"(uid=$username)"
    val searchControls = new SearchControls()
    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE)
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
  }
}

// Example 2: LDAP injection with string concatenation
class bad_case_2 extends Controller {
  def searchUser = Action { request =>
    val username = request.getQueryString("username").getOrElse("")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = "(uid=" + username + ")"
    val searchControls = new SearchControls()
    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE)
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    Ok("Search completed")
  }
}

// Example 3: LDAP injection with multiple user inputs
@Controller
class bad_case_3 {
  @GetMapping(Array("/search"))
  def searchUsers(request: HttpServletRequest): ResponseEntity[String] = {
    val firstName = request.getParameter("firstName")
    val lastName = request.getParameter("lastName")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = s"(&(givenName=$firstName)(sn=$lastName))"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    ResponseEntity.ok("Search completed")
  }
}

// Example 4: LDAP injection in Play Framework
class bad_case_4 extends Controller {
  def authenticate() = Action { request =>
    val json = request.body.asJson.getOrElse(Json.obj())
    val username = (json \ "username").asOpt[String].getOrElse("")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = s"(sAMAccountName=$username)"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    Ok(Json.obj("status" -> "success"))
  }
}

// Example 5: LDAP injection with form data
class bad_case_5 extends Controller {
  def findEmployee() = Action { request =>
    val formData = request.body.asFormUrlEncoded
    val employeeId = formData.flatMap(_.get("employeeId").flatMap(_.headOption)).getOrElse("")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = "(employeeNumber=" + employeeId + ")"
    val searchControls = new SearchControls()
    val results = ctx.search("ou=employees,dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    Ok("Employee search completed")
  }
}

// Example 6: LDAP injection with minimal processing
class bad_case_6 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val email = request.getParameter("email").trim.toLowerCase
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = s"(mail=$email)"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
  }
}

// Example 7: LDAP injection with header input
class bad_case_7 extends Controller {
  def verifyUser() = Action { request =>
    val authHeader = request.headers.get("X-Auth-Username").getOrElse("")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = "(uid=" + authHeader + ")"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    Ok("Verification completed")
  }
}

// Example 8: LDAP injection with cookie data
class bad_case_8 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val cookies = request.getCookies()
    val usernameCookie = cookies.find(_.getName == "username").map(_.getValue).getOrElse("")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = s"(cn=$usernameCookie)"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
  }
}

// Example 9: LDAP injection with complex filter
@Controller
class bad_case_9 {
  @PostMapping(Array("/search"))
  def searchDirectory(request: HttpServletRequest): ResponseEntity[String] = {
    val department = request.getParameter("department")
    val role = request.getParameter("role")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = s"(&(department=$department)(title=$role))"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    ResponseEntity.ok("Search completed")
  }
}

// Example 10: LDAP injection with Akka HTTP
class bad_case_10 {
  val route: Route = {
    path("users") {
      get {
        parameter("username") { username =>
          val env = new java.util.Hashtable[String, String]()
          env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
          env.put(Context.PROVIDER_URL, "ldap://localhost:389")
          
          val ctx = new InitialDirContext(env)
          
          // ruleid: scala-ldap-injection
          val searchFilter = s"(uid=$username)"
          val searchControls = new SearchControls()
          val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
          
          // Process results...
          ctx.close()
          
          complete(HttpResponse(status = 200))
        }
      }
    }
  }
}

// Example 11: LDAP injection with multiple attributes in filter
class bad_case_11 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val name = request.getParameter("name")
    val email = request.getParameter("email")
    val phone = request.getParameter("phone")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = s"(|(cn=$name)(mail=$email)(telephoneNumber=$phone))"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
  }
}

// Example 12: LDAP injection with indirect string construction
class bad_case_12 extends Controller {
  def findUser() = Action { request =>
    val username = request.getQueryString("username").getOrElse("")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    val attributeName = "uid"
    val attributeValue = username
    
    // ruleid: scala-ldap-injection
    val searchFilter = s"($attributeName=$attributeValue)"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    Ok("Search completed")
  }
}

// Example 13: LDAP injection with JSON body parsing
class bad_case_13 extends Controller {
  def searchGroups() = Action(parse.json) { request =>
    val json = request.body
    val groupName = (json \ "groupName").asOpt[String].getOrElse("")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = "(cn=" + groupName + ")"
    val searchControls = new SearchControls()
    val results = ctx.search("ou=groups,dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    Ok(Json.obj("status" -> "success"))
  }
}

// Example 14: LDAP injection with path parameter
@Controller
class bad_case_14 {
  @GetMapping(Array("/users/{username}"))
  def getUser(@PathVariable("username") username: String): ResponseEntity[String] = {
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = s"(sAMAccountName=$username)"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    ResponseEntity.ok("User found")
  }
}

// Example 15: LDAP injection with string interpolation in complex query
class bad_case_15 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val firstName = request.getParameter("firstName")
    val lastName = request.getParameter("lastName")
    val department = request.getParameter("department")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ruleid: scala-ldap-injection
    val searchFilter = s"(&(givenName=$firstName)(sn=$lastName)(department=$department))"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
  }
}

// True Negative Examples (Safe Code)

// Example 1: Safe LDAP query with proper escaping
class good_case_1 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val username = request.getParameter("username")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ok: scala-ldap-injection
    val escapedUsername = escapeLDAPSearchFilter(username)
    val searchFilter = s"(uid=$escapedUsername)"
    val searchControls = new SearchControls()
    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE)
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
  }
  
  private def escapeLDAPSearchFilter(filter: String): String = {
    val sb = new StringBuilder()
    for (i <- 0 until filter.length) {
      val c = filter.charAt(i)
      c match {
        case '\\' => sb.append("\\5c")
        case '*' => sb.append("\\2a")
        case '(' => sb.append("\\28")
        case ')' => sb.append("\\29")
        case '\u0000' => sb.append("\\00")
        case '/' => sb.append("\\2f")
        case _ => sb.append(c)
      }
    }
    sb.toString
  }
}

// Example 2: Safe LDAP query using Apache Commons Text for escaping
class good_case_2 extends Controller {
  def searchUser = Action { request =>
    val username = request.getQueryString("username").getOrElse("")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ok: scala-ldap-injection
    val escapedUsername = StringEscapeUtils.escapeJava(username)
      .replace("(", "\\28")
      .replace(")", "\\29")
      .replace("*", "\\2a")
      .replace("\\", "\\5c")
    
    val searchFilter = "(uid=" + escapedUsername + ")"
    val searchControls = new SearchControls()
    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE)
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    Ok("Search completed")
  }
}

// Example 3: Safe LDAP query with whitelist validation
@Controller
class good_case_3 {
  @GetMapping(Array("/search"))
  def searchUsers(request: HttpServletRequest): ResponseEntity[String] = {
    val firstName = request.getParameter("firstName")
    val lastName = request.getParameter("lastName")
    
    // ok: scala-ldap-injection
    if (!isValidInput(firstName) || !isValidInput(lastName)) {
      return ResponseEntity.badRequest().body("Invalid input")
    }
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    val searchFilter = s"(&(givenName=$firstName)(sn=$lastName))"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    ResponseEntity.ok("Search completed")
  }
  
  private def isValidInput(input: String): Boolean = {
    // Only allow alphanumeric characters and spaces
    input != null && input.matches("^[a-zA-Z0-9 ]+$")
  }
}

// Example 4: Safe LDAP query using parameterized filters
class good_case_4 extends Controller {
  def authenticate() = Action { request =>
    val json = request.body.asJson.getOrElse(Json.obj())
    val username = (json \ "username").asOpt[String].getOrElse("")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ok: scala-ldap-injection
    val searchAttributes = new BasicAttributes(true)
    searchAttributes.put(new BasicAttribute("sAMAccountName", username))
    val results = ctx.search("dc=example,dc=com", searchAttributes)
    
    // Process results...
    ctx.close()
    
    Ok(Json.obj("status" -> "success"))
  }
}

// Example 5: Safe LDAP query with regex pattern matching
class good_case_5 extends Controller {
  def findEmployee() = Action { request =>
    val formData = request.body.asFormUrlEncoded
    val employeeId = formData.flatMap(_.get("employeeId").flatMap(_.headOption)).getOrElse("")
    
    // ok: scala-ldap-injection
    if (!employeeId.matches("^[0-9]{6}$")) {
      return BadRequest("Invalid employee ID format")
    }
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    val searchFilter = "(employeeNumber=" + employeeId + ")"
    val searchControls = new SearchControls()
    val results = ctx.search("ou=employees,dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    Ok("Employee search completed")
  }
}

// Example 6: Safe LDAP query with custom sanitization function
class good_case_6 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val email = request.getParameter("email").trim.toLowerCase
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ok: scala-ldap-injection
    val sanitizedEmail = sanitizeLdapInput(email)
    val searchFilter = s"(mail=$sanitizedEmail)"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
  }
  
  private def sanitizeLdapInput(input: String): String = {
    val specialChars = List('\\', '*', '(', ')', '\u0000')
    specialChars.foldLeft(input) { (result, char) =>
      result.replace(char.toString, s"\\${char.toInt.toHexString}")
    }
  }
}

// Example 7: Safe LDAP query with header input and validation
class good_case_7 extends Controller {
  def verifyUser() = Action { request =>
    val authHeader = request.headers.get("X-Auth-Username").getOrElse("")
    
    // ok: scala-ldap-injection
    if (!authHeader.matches("^[a-zA-Z0-9._-]{3,20}$")) {
      return BadRequest("Invalid username format")
    }
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    val searchFilter = "(uid=" + authHeader + ")"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    Ok("Verification completed")
  }
}

// Example 8: Safe LDAP query with prepared filter
class good_case_8 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val cookies = request.getCookies()
    val usernameCookie = cookies.find(_.getName == "username").map(_.getValue).getOrElse("")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ok: scala-ldap-injection
    val attrs = new BasicAttributes()
    attrs.put("cn", usernameCookie)
    val results = ctx.search("dc=example,dc=com", attrs)
    
    // Process results...
    ctx.close()
  }
}

// Example 9: Safe LDAP query with input validation and sanitization
@Controller
class good_case_9 {
  @PostMapping(Array("/search"))
  def searchDirectory(request: HttpServletRequest): ResponseEntity[String] = {
    val department = request.getParameter("department")
    val role = request.getParameter("role")
    
    // ok: scala-ldap-injection
    if (!isValidDepartment(department) || !isValidRole(role)) {
      return ResponseEntity.badRequest().body("Invalid input parameters")
    }
    
    val sanitizedDept = sanitizeLdapInput(department)
    val sanitizedRole = sanitizeLdapInput(role)
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    val searchFilter = s"(&(department=$sanitizedDept)(title=$sanitizedRole))"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    ResponseEntity.ok("Search completed")
  }
  
  private def isValidDepartment(dept: String): Boolean = {
    val validDepartments = List("IT", "HR", "Finance", "Marketing", "Sales")
    validDepartments.contains(dept)
  }
  
  private def isValidRole(role: String): Boolean = {
    val validRoles = List("Manager", "Director", "Associate", "Analyst", "Engineer")
    validRoles.contains(role)
  }
  
  private def sanitizeLdapInput(input: String): String = {
    input.replaceAll("[\\\\*()\\0/]", "")
  }
}

// Example 10: Safe LDAP query with Akka HTTP and proper escaping
class good_case_10 {
  val route: Route = {
    path("users") {
      get {
        parameter("username") { username =>
          val env = new java.util.Hashtable[String, String]()
          env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
          env.put(Context.PROVIDER_URL, "ldap://localhost:389")
          
          val ctx = new InitialDirContext(env)
          
          // ok: scala-ldap-injection
          val escapedUsername = username
            .replace("\\", "\\5c")
            .replace("*", "\\2a")
            .replace("(", "\\28")
            .replace(")", "\\29")
          
          val searchFilter = s"(uid=$escapedUsername)"
          val searchControls = new SearchControls()
          val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
          
          // Process results...
          ctx.close()
          
          complete(HttpResponse(status = 200))
        }
      }
    }
  }
}

// Example 11: Safe LDAP query with multiple attributes and proper escaping
class good_case_11 extends HttpServlet {
  override def doGet(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val name = request.getParameter("name")
    val email = request.getParameter("email")
    val phone = request.getParameter("phone")
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ok: scala-ldap-injection
    val escapedName = escapeLdapSearchFilter(name)
    val escapedEmail = escapeLdapSearchFilter(email)
    val escapedPhone = escapeLdapSearchFilter(phone)
    
    val searchFilter = s"(|(cn=$escapedName)(mail=$escapedEmail)(telephoneNumber=$escapedPhone))"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
  }
  
  private def escapeLdapSearchFilter(filter: String): String = {
    if (filter == null) return ""
    filter.replace("\\", "\\5c")
          .replace("*", "\\2a")
          .replace("(", "\\28")
          .replace(")", "\\29")
          .replace("\u0000", "\\00")
  }
}

// Example 12: Safe LDAP query using a whitelist approach
class good_case_12 extends Controller {
  def findUser() = Action { request =>
    val username = request.getQueryString("username").getOrElse("")
    
    // ok: scala-ldap-injection
    val allowedUsernames = List("admin", "user1", "user2", "guest")
    if (!allowedUsernames.contains(username)) {
      return BadRequest("Invalid username")
    }
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    val searchFilter = s"(uid=$username)"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    Ok("Search completed")
  }
}

// Example 13: Safe LDAP query with JSON body parsing and validation
class good_case_13 extends Controller {
  def searchGroups() = Action(parse.json) { request =>
    val json = request.body
    val groupName = (json \ "groupName").asOpt[String].getOrElse("")
    
    // ok: scala-ldap-injection
    if (!groupName.matches("^[a-zA-Z0-9-_]{3,50}$")) {
      return BadRequest(Json.obj("error" -> "Invalid group name format"))
    }
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    val searchFilter = "(cn=" + groupName + ")"
    val searchControls = new SearchControls()
    val results = ctx.search("ou=groups,dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    Ok(Json.obj("status" -> "success"))
  }
}

// Example 14: Safe LDAP query with path parameter and escaping
@Controller
class good_case_14 {
  @GetMapping(Array("/users/{username}"))
  def getUser(@PathVariable("username") username: String): ResponseEntity[String] = {
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    // ok: scala-ldap-injection
    val escapedUsername = username
      .replace("\\", "\\\\")
      .replace("*", "\\*")
      .replace("(", "\\(")
      .replace(")", "\\)")
      .replace("\u0000", "")
    
    val searchFilter = s"(sAMAccountName=$escapedUsername)"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
    
    ResponseEntity.ok("User found")
  }
}

// Example 15: Safe LDAP query with type conversion and validation
class good_case_15 extends HttpServlet {
  override def doPost(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val firstName = request.getParameter("firstName")
    val lastName = request.getParameter("lastName")
    val departmentId = request.getParameter("department")
    
    // ok: scala-ldap-injection
    if (!isValidName(firstName) || !isValidName(lastName)) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid name format")
      return
    }
    
    val department = Try(departmentId.toInt).toOption match {
      case Some(id) if id >= 100 && id <= 999 => id.toString
      case _ => 
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid department ID")
        return
    }
    
    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://localhost:389")
    
    val ctx = new InitialDirContext(env)
    
    val searchFilter = s"(&(givenName=$firstName)(sn=$lastName)(departmentNumber=$department))"
    val searchControls = new SearchControls()
    val results = ctx.search("dc=example,dc=com", searchFilter, searchControls)
    
    // Process results...
    ctx.close()
  }
  
  private def isValidName(name: String): Boolean = {
    name != null && name.matches("^[a-zA-Z\\s-]{2,50}$")
  }
}