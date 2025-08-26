import java.sql.{Connection, DriverManager, PreparedStatement, Statement}
import scala.io.Source
import play.api.mvc._
import play.api.http._
import play.api.libs.json._
import scala.concurrent.{ExecutionContext, Future}
import javax.inject.Inject
import play.api.db.Database
import scala.util.{Try, Success, Failure}
import org.apache.commons.text.StringEscapeUtils
import scala.collection.mutable.ListBuffer
// {fact rule=cross-site-scripting@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(implicit request: Request[AnyContent]): Unit = {
  val userId = request.getQueryString("userId").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.executeQuery(s"SELECT * FROM users WHERE id = $userId")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_2(implicit request: Request[AnyContent]): Unit = {
  val username = request.body.asFormUrlEncoded.get("username").head
  val conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password")
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.executeUpdate(s"UPDATE users SET active = true WHERE username = '$username'")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_3(implicit request: Request[AnyContent]): Unit = {
  val searchTerm = request.headers.get("X-Search-Term").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "")
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.execute(s"DELETE FROM products WHERE name LIKE '%$searchTerm%'")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_4(implicit request: Request[AnyContent]): Unit = {
  val sortColumn = request.getQueryString("sort").getOrElse("id")
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  val resultSet = statement.executeQuery(s"SELECT * FROM users ORDER BY $sortColumn")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_5(implicit request: Request[AnyContent]): Unit = {
  val tableName = request.getQueryString("table").getOrElse("users")
  val conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password")
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.executeQuery(s"SELECT COUNT(*) FROM $tableName")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_6(implicit request: Request[AnyContent], db: Database): Unit = {
  val userIds = request.body.asJson.get("userIds").as[List[String]].mkString(",")
  val conn = db.getConnection()
  try {
    val statement = conn.createStatement()
    // ruleid: scala-sql-injection-ide
    statement.executeQuery(s"SELECT * FROM users WHERE id IN ($userIds)")
  } finally {
    conn.close()
  }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_7(implicit request: Request[AnyContent]): Unit = {
  val category = request.cookies.get("category").map(_.value).getOrElse("default")
  val limit = request.getQueryString("limit").getOrElse("10")
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.executeQuery(s"SELECT * FROM products WHERE category = '$category' LIMIT $limit")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_8(implicit request: Request[AnyContent]): Unit = {
  val searchFields = request.body.asFormUrlEncoded.get("fields").mkString(",")
  val conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password")
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.executeQuery(s"SELECT $searchFields FROM users")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_9(implicit request: Request[AnyContent]): Unit = {
  val userId = request.getQueryString("userId").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "")
  
  // Still vulnerable even with string concatenation
  val sql = "SELECT * FROM users WHERE id = " + userId
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.executeQuery(sql)
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_10(implicit request: Request[AnyContent]): Unit = {
  val email = request.body.asJson.get("email").as[String]
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  
  // Vulnerable with multiple conditions
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.executeQuery(s"SELECT * FROM users WHERE active = true AND email = '$email'")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_11(implicit request: Request[AnyContent]): Unit = {
  val columns = request.getQueryString("columns").getOrElse("*")
  val table = request.getQueryString("table").getOrElse("users")
  val conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password")
  
  // Multiple user inputs in the same query
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.executeQuery(s"SELECT $columns FROM $table")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_12(implicit request: Request[AnyContent]): Unit = {
  val id = request.getQueryString("id").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  
  // Vulnerable with string interpolation in a variable
  val sql = s"DELETE FROM users WHERE id = $id"
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.executeUpdate(sql)
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_13(implicit request: Request[AnyContent]): Unit = {
  val searchTerm = request.body.asFormUrlEncoded.get("search").head
  val conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "")
  
  // Vulnerable with string formatting
  val sql = "SELECT * FROM products WHERE name LIKE '%%%s%%'".format(searchTerm)
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.executeQuery(sql)
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_14(implicit request: Request[AnyContent]): Unit = {
  val userId = request.getQueryString("userId").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  
  // Vulnerable with StringBuilder
  val sqlBuilder = new StringBuilder("SELECT * FROM users WHERE id = ")
  sqlBuilder.append(userId)
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.executeQuery(sqlBuilder.toString())
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_15(implicit request: Request[AnyContent]): Unit = {
  val conditions = ListBuffer[String]()
  
  if (request.getQueryString("name").isDefined) {
    conditions += s"name = '${request.getQueryString("name").get}'"
  }
  
  if (request.getQueryString("age").isDefined) {
    conditions += s"age = ${request.getQueryString("age").get}"
  }
  
  val whereClause = if (conditions.nonEmpty) s"WHERE ${conditions.mkString(" AND ")}" else ""
  val conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password")
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection-ide
  statement.executeQuery(s"SELECT * FROM users $whereClause")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// True Negative Examples (Safe Code)

def good_case_1(implicit request: Request[AnyContent]): Unit = {
  val userId = request.getQueryString("userId").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  // ok: scala-sql-injection-ide
  val preparedStatement = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
  preparedStatement.setString(1, userId)
  preparedStatement.executeQuery()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_2(implicit request: Request[AnyContent]): Unit = {
  val username = request.body.asFormUrlEncoded.get("username").head
  val conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password")
  // ok: scala-sql-injection-ide
  val preparedStatement = conn.prepareStatement("UPDATE users SET active = true WHERE username = ?")
  preparedStatement.setString(1, username)
  preparedStatement.executeUpdate()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_3(implicit request: Request[AnyContent]): Unit = {
  val searchTerm = request.headers.get("X-Search-Term").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "")
  // ok: scala-sql-injection-ide
  val preparedStatement = conn.prepareStatement("DELETE FROM products WHERE name LIKE ?")
  preparedStatement.setString(1, "%" + searchTerm + "%")
  preparedStatement.execute()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_4(implicit request: Request[AnyContent]): Unit = {
  val sortColumn = request.getQueryString("sort").getOrElse("id")
  // Validate the column name against a whitelist
  val allowedColumns = Set("id", "name", "email", "created_at")
  val safeColumn = if (allowedColumns.contains(sortColumn)) sortColumn else "id"
  
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  // ok: scala-sql-injection-ide
  val resultSet = statement.executeQuery(s"SELECT * FROM users ORDER BY $safeColumn")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_5(implicit request: Request[AnyContent]): Unit = {
  val tableName = request.getQueryString("table").getOrElse("users")
  // Validate the table name against a whitelist
  val allowedTables = Set("users", "products", "orders")
  val safeTable = if (allowedTables.contains(tableName)) tableName else "users"
  
  val conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password")
  val statement = conn.createStatement()
  // ok: scala-sql-injection-ide
  statement.executeQuery(s"SELECT COUNT(*) FROM $safeTable")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_6(implicit request: Request[AnyContent], db: Database): Unit = {
  val userIds = request.body.asJson.get("userIds").as[List[String]]
  val conn = db.getConnection()
  try {
    // ok: scala-sql-injection-ide
    val placeholders = userIds.map(_ => "?").mkString(",")
    val preparedStatement = conn.prepareStatement(s"SELECT * FROM users WHERE id IN ($placeholders)")
    userIds.zipWithIndex.foreach { case (id, index) =>
      preparedStatement.setString(index + 1, id)
    }
    preparedStatement.executeQuery()
  } finally {
    conn.close()
  }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_7(implicit request: Request[AnyContent]): Unit = {
  val category = request.cookies.get("category").map(_.value).getOrElse("default")
  val limit = Try(request.getQueryString("limit").getOrElse("10").toInt).getOrElse(10)
  // Validate the limit
  val safeLimit = Math.min(Math.max(1, limit), 100)
  
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  // ok: scala-sql-injection-ide
  val preparedStatement = conn.prepareStatement("SELECT * FROM products WHERE category = ? LIMIT ?")
  preparedStatement.setString(1, category)
  preparedStatement.setInt(2, safeLimit)
  preparedStatement.executeQuery()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_8(implicit request: Request[AnyContent]): Unit = {
  val requestedFields = request.body.asFormUrlEncoded.get("fields")
  // Validate the fields against a whitelist
  val allowedFields = Set("id", "name", "email", "created_at")
  val safeFields = requestedFields.filter(allowedFields.contains).mkString(",")
  val fieldsToUse = if (safeFields.isEmpty) "id" else safeFields
  
  val conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password")
  val statement = conn.createStatement()
  // ok: scala-sql-injection-ide
  statement.executeQuery(s"SELECT $fieldsToUse FROM users")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_9(implicit request: Request[AnyContent]): Unit = {
  val userId = request.getQueryString("userId").getOrElse("")
  // Validate that userId is numeric
  if (!userId.matches("\\d+")) {
    throw new IllegalArgumentException("Invalid user ID")
  }
  
  val conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "")
  val statement = conn.createStatement()
  // ok: scala-sql-injection-ide
  statement.executeQuery(s"SELECT * FROM users WHERE id = $userId")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_10(implicit request: Request[AnyContent]): Unit = {
  val email = request.body.asJson.get("email").as[String]
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  
  // Using prepared statement with multiple conditions
  // ok: scala-sql-injection-ide
  val preparedStatement = conn.prepareStatement("SELECT * FROM users WHERE active = true AND email = ?")
  preparedStatement.setString(1, email)
  preparedStatement.executeQuery()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_11(implicit request: Request[AnyContent]): Unit = {
  val columns = request.getQueryString("columns").getOrElse("*")
  val table = request.getQueryString("table").getOrElse("users")
  
  // Validate against whitelists
  val allowedColumns = Set("*", "id", "name", "email")
  val allowedTables = Set("users", "products")
  
  val safeColumns = if (allowedColumns.contains(columns)) columns else "*"
  val safeTable = if (allowedTables.contains(table)) table else "users"
  
  val conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password")
  val statement = conn.createStatement()
  // ok: scala-sql-injection-ide
  statement.executeQuery(s"SELECT $safeColumns FROM $safeTable")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_12(implicit request: Request[AnyContent]): Unit = {
  val id = request.getQueryString("id").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  
  // Using prepared statement for DELETE
  // ok: scala-sql-injection-ide
  val preparedStatement = conn.prepareStatement("DELETE FROM users WHERE id = ?")
  preparedStatement.setString(1, id)
  preparedStatement.executeUpdate()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_13(implicit request: Request[AnyContent]): Unit = {
  val searchTerm = request.body.asFormUrlEncoded.get("search").head
  val conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "")
  
  // Escaping the search term
  val escapedTerm = StringEscapeUtils.escapeSql(searchTerm)
  val statement = conn.createStatement()
  // ok: scala-sql-injection-ide
  statement.executeQuery(s"SELECT * FROM products WHERE name LIKE '%$escapedTerm%'")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_14(implicit request: Request[AnyContent]): Unit = {
  val userId = request.getQueryString("userId").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  
  // Using anorm with parameterized query (Play Framework)
  import anorm._
  import anorm.SqlParser._
  
  // ok: scala-sql-injection-ide
  val result = SQL"SELECT * FROM users WHERE id = $userId".as(str("name").*)
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_15(implicit request: Request[AnyContent]): Unit = {
  val name = request.getQueryString("name")
  val age = request.getQueryString("age").flatMap(a => Try(a.toInt).toOption)
  
  val conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password")
  
  // Building a prepared statement dynamically
  val conditions = new ListBuffer[(String, Any)]()
  
  if (name.isDefined) {
    conditions += (("name = ?", name.get))
  }
  
  if (age.isDefined) {
    conditions += (("age = ?", age.get))
  }
  
  val whereClause = if (conditions.nonEmpty) {
    "WHERE " + conditions.map(_._1).mkString(" AND ")
  } else {
    ""
  }
  
  // ok: scala-sql-injection-ide
  val preparedStatement = conn.prepareStatement(s"SELECT * FROM users $whereClause")
  conditions.zipWithIndex.foreach { case ((_, value), index) =>
    value match {
      case s: String => preparedStatement.setString(index + 1, s)
      case i: Int => preparedStatement.setInt(index + 1, i)
      case _ => // Handle other types
    }
  }
  preparedStatement.executeQuery()
  conn.close()
}
// {/fact}