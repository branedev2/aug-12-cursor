import java.sql.{Connection, DriverManager, PreparedStatement, Statement}
import scala.io.Source
import play.api.mvc._
import play.api.http._
import play.api.libs.json._
import scala.util.{Try, Success, Failure}
import org.apache.commons.lang3.StringEscapeUtils
import javax.inject.Inject
import play.api.db.Database
import scala.collection.mutable.Map
// {fact rule=cross-site-scripting@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(request: Request[AnyContent]): Unit = {
  val userId = request.getQueryString("id").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery(s"SELECT * FROM users WHERE id = $userId")
  
  // Process results
  while (resultSet.next()) {
    println(resultSet.getString("username"))
  }
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_2(request: Request[AnyContent]): Unit = {
  val username = request.body.asFormUrlEncoded.get("username").head
  val conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password")
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection
  statement.executeUpdate(s"UPDATE users SET active = true WHERE username = '$username'")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_3(request: Request[AnyContent]): Unit = {
  val searchTerm = request.getQueryString("search").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val sql = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'"
  val statement = conn.createStatement()
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery(sql)
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_4(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  val sortColumn = request.getQueryString("sort").getOrElse("id")
  val sortOrder = request.getQueryString("order").getOrElse("ASC")
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery(s"SELECT * FROM products ORDER BY $sortColumn $sortOrder")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_5(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  val json = request.body.asJson.get
  val userId = (json \ "userId").as[String]
  // ruleid: scala-sql-injection
  statement.executeUpdate(s"DELETE FROM users WHERE id = $userId")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_6(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  val headers = request.headers
  val apiKey = headers.get("X-API-Key").getOrElse("")
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery(s"SELECT * FROM api_users WHERE api_key = '$apiKey'")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_7(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  val cookie = request.cookies.get("user_id")
  val userId = cookie.map(_.value).getOrElse("")
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery(s"SELECT * FROM sessions WHERE user_id = '$userId'")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_8(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  val formData = request.body.asFormUrlEncoded.getOrElse(Map.empty)
  val minPrice = formData.getOrElse("min_price", Seq("0")).head
  val maxPrice = formData.getOrElse("max_price", Seq("1000")).head
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery(s"SELECT * FROM products WHERE price BETWEEN $minPrice AND $maxPrice")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_9(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  val categoryIds = request.getQueryString("categories").getOrElse("1,2,3")
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery(s"SELECT * FROM products WHERE category_id IN ($categoryIds)")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_10(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  val json = request.body.asJson.get
  val table = (json \ "table").as[String]
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery(s"SELECT COUNT(*) FROM $table")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_11(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  val userId = request.getQueryString("id").getOrElse("")
  val userInput = "'" + userId + "'"
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery("SELECT * FROM users WHERE id = " + userInput)
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_12(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  val json = request.body.asJson.get
  val fields = (json \ "fields").as[String]
  val table = (json \ "table").as[String]
  val whereClause = (json \ "where").as[String]
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery(s"SELECT $fields FROM $table WHERE $whereClause")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_13(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  val email = request.getQueryString("email").getOrElse("")
  val domain = email.split("@").lastOption.getOrElse("")
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery(s"SELECT * FROM domains WHERE name = '$domain'")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_14(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  val searchParams = request.queryString.map { case (k, v) => k -> v.mkString }
  val whereClause = searchParams.map { case (key, value) => s"$key = '$value'" }.mkString(" AND ")
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery(s"SELECT * FROM products WHERE $whereClause")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

def bad_case_15(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val statement = conn.createStatement()
  val limit = request.getQueryString("limit").getOrElse("10")
  val offset = request.getQueryString("offset").getOrElse("0")
  // ruleid: scala-sql-injection
  val resultSet = statement.executeQuery(s"SELECT * FROM products LIMIT $limit OFFSET $offset")
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// True Negative Examples (Secure Code)

def good_case_1(request: Request[AnyContent]): Unit = {
  val userId = request.getQueryString("id").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  // ok: scala-sql-injection
  val preparedStatement = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
  preparedStatement.setString(1, userId)
  val resultSet = preparedStatement.executeQuery()
  
  // Process results
  while (resultSet.next()) {
    println(resultSet.getString("username"))
  }
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_2(request: Request[AnyContent]): Unit = {
  val username = request.body.asFormUrlEncoded.get("username").head
  val conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/mydb", "user", "password")
  // ok: scala-sql-injection
  val preparedStatement = conn.prepareStatement("UPDATE users SET active = true WHERE username = ?")
  preparedStatement.setString(1, username)
  preparedStatement.executeUpdate()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_3(request: Request[AnyContent]): Unit = {
  val searchTerm = request.getQueryString("search").getOrElse("")
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  // ok: scala-sql-injection
  val preparedStatement = conn.prepareStatement("SELECT * FROM products WHERE name LIKE ?")
  preparedStatement.setString(1, "%" + searchTerm + "%")
  val resultSet = preparedStatement.executeQuery()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_4(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val sortColumn = request.getQueryString("sort").getOrElse("id")
  val sortOrder = request.getQueryString("order").getOrElse("ASC")
  
  // Validate sort column against allowed values
  val allowedColumns = List("id", "name", "price", "created_at")
  val validatedColumn = if (allowedColumns.contains(sortColumn)) sortColumn else "id"
  
  // Validate sort order
  val validatedOrder = if (sortOrder == "DESC") "DESC" else "ASC"
  
  // ok: scala-sql-injection
  val preparedStatement = conn.prepareStatement(s"SELECT * FROM products ORDER BY $validatedColumn $validatedOrder")
  val resultSet = preparedStatement.executeQuery()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_5(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val json = request.body.asJson.get
  val userId = (json \ "userId").as[String]
  // ok: scala-sql-injection
  val preparedStatement = conn.prepareStatement("DELETE FROM users WHERE id = ?")
  preparedStatement.setString(1, userId)
  preparedStatement.executeUpdate()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_6(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val headers = request.headers
  val apiKey = headers.get("X-API-Key").getOrElse("")
  // ok: scala-sql-injection
  val preparedStatement = conn.prepareStatement("SELECT * FROM api_users WHERE api_key = ?")
  preparedStatement.setString(1, apiKey)
  val resultSet = preparedStatement.executeQuery()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_7(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val cookie = request.cookies.get("user_id")
  val userId = cookie.map(_.value).getOrElse("")
  // ok: scala-sql-injection
  val preparedStatement = conn.prepareStatement("SELECT * FROM sessions WHERE user_id = ?")
  preparedStatement.setString(1, userId)
  val resultSet = preparedStatement.executeQuery()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_8(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val formData = request.body.asFormUrlEncoded.getOrElse(Map.empty)
  val minPrice = formData.getOrElse("min_price", Seq("0")).head
  val maxPrice = formData.getOrElse("max_price", Seq("1000")).head
  
  // ok: scala-sql-injection
  val preparedStatement = conn.prepareStatement("SELECT * FROM products WHERE price BETWEEN ? AND ?")
  try {
    preparedStatement.setDouble(1, minPrice.toDouble)
    preparedStatement.setDouble(2, maxPrice.toDouble)
    val resultSet = preparedStatement.executeQuery()
  } catch {
    case e: NumberFormatException => 
      // Handle invalid number format
      println("Invalid price format")
  }
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_9(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val categoryIdsString = request.getQueryString("categories").getOrElse("1,2,3")
  val categoryIds = categoryIdsString.split(",").toList
  
  // Create a prepared statement with the right number of placeholders
  val placeholders = categoryIds.map(_ => "?").mkString(",")
  // ok: scala-sql-injection
  val preparedStatement = conn.prepareStatement(s"SELECT * FROM products WHERE category_id IN ($placeholders)")
  
  // Set each parameter
  categoryIds.zipWithIndex.foreach { case (id, index) =>
    try {
      preparedStatement.setInt(index + 1, id.toInt)
    } catch {
      case e: NumberFormatException => preparedStatement.setInt(index + 1, 0)
    }
  }
  
  val resultSet = preparedStatement.executeQuery()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_10(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val json = request.body.asJson.get
  val table = (json \ "table").as[String]
  
  // Validate table name against allowed values
  val allowedTables = List("products", "categories", "users")
  val validatedTable = if (allowedTables.contains(table)) table else "products"
  
  // ok: scala-sql-injection
  val preparedStatement = conn.prepareStatement(s"SELECT COUNT(*) FROM $validatedTable")
  val resultSet = preparedStatement.executeQuery()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_11(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val userId = request.getQueryString("id").getOrElse("")
  
  // Use a database access layer that handles parameterization
  class SafeDbAccess(conn: Connection) {
    def getUserById(id: String): ResultSet = {
      // ok: scala-sql-injection
      val preparedStatement = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
      preparedStatement.setString(1, id)
      preparedStatement.executeQuery()
    }
  }
  
  val dbAccess = new SafeDbAccess(conn)
  val resultSet = dbAccess.getUserById(userId)
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_12(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  
  // Using Anorm (Play Framework SQL library) which handles parameterization
  import anorm._
  import anorm.SqlParser._
  
  val id = request.getQueryString("id").getOrElse("")
  
  // ok: scala-sql-injection
  val result = SQL"SELECT * FROM users WHERE id = $id".as(
    (str("id") ~ str("name") ~ str("email")).map {
      case id ~ name ~ email => (id, name, email)
    }.*)
  
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_13(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val email = request.getQueryString("email").getOrElse("")
  val domain = email.split("@").lastOption.getOrElse("")
  
  // ok: scala-sql-injection
  val preparedStatement = conn.prepareStatement("SELECT * FROM domains WHERE name = ?")
  preparedStatement.setString(1, domain)
  val resultSet = preparedStatement.executeQuery()
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_14(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val searchParams = request.queryString.map { case (k, v) => k -> v.mkString }
  
  // Build a safe query with parameters
  val allowedFields = List("name", "category", "status")
  val validParams = searchParams.filter { case (key, _) => allowedFields.contains(key) }
  
  if (validParams.nonEmpty) {
    val whereClause = validParams.keys.map(_ + " = ?").mkString(" AND ")
    // ok: scala-sql-injection
    val preparedStatement = conn.prepareStatement(s"SELECT * FROM products WHERE $whereClause")
    
    validParams.values.zipWithIndex.foreach { case (value, index) =>
      preparedStatement.setString(index + 1, value)
    }
    
    val resultSet = preparedStatement.executeQuery()
  }
  conn.close()
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

def good_case_15(request: Request[AnyContent]): Unit = {
  val conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password")
  val limitStr = request.getQueryString("limit").getOrElse("10")
  val offsetStr = request.getQueryString("offset").getOrElse("0")
  
  // Parse and validate numeric parameters
  val limit = Try(limitStr.toInt).getOrElse(10).max(1).min(100) // Limit between 1 and 100
  val offset = Try(offsetStr.toInt).getOrElse(0).max(0) // Offset minimum 0
  
  // ok: scala-sql-injection
  val preparedStatement = conn.prepareStatement("SELECT * FROM products LIMIT ? OFFSET ?")
  preparedStatement.setInt(1, limit)
  preparedStatement.setInt(2, offset)
  val resultSet = preparedStatement.executeQuery()
  conn.close()
}
// {/fact}