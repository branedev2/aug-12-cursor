import com.amazonaws.services.simpledb._
import com.amazonaws.services.simpledb.model._
import com.amazonaws.auth.{AWSStaticCredentialsProvider, BasicAWSCredentials}
import com.amazonaws.regions.Regions
import scala.collection.JavaConverters._
import scala.io.Source
import play.api.mvc._
import play.api.http.HttpEntity
import play.api.libs.json._
import javax.inject.Inject
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.model.{HttpRequest, HttpResponse}
import akka.http.scaladsl.unmarshalling.Unmarshal
import akka.http.scaladsl.model.headers.RawHeader
import scala.concurrent.{ExecutionContext, Future}
// {fact rule=nosql-injection@v1.0 defects=1}

// True positives (vulnerable code examples)

def bad_case_1(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userId = request.getQueryString("userId").getOrElse("")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  val selectRequest = new SelectRequest()
  
  // ruleid: scala-simple-db-query-injection
  selectRequest.setSelectExpression("SELECT * FROM users WHERE userId = '" + userId + "'")
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

def bad_case_2(request: play.api.mvc.Request[AnyContent]): Unit = {
  val username = request.body.asFormUrlEncoded.get("username").head
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ruleid: scala-simple-db-query-injection
  val query = s"SELECT * FROM users WHERE username = '$username' AND active = 'true'"
  val selectRequest = new SelectRequest(query)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

def bad_case_3(request: play.api.mvc.Request[AnyContent]): Unit = {
  val productId = request.headers.get("X-Product-Id").getOrElse("")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  val selectRequest = new SelectRequest()
  
  // ruleid: scala-simple-db-query-injection
  selectRequest.setSelectExpression("SELECT * FROM products WHERE productId = \"" + productId + "\"")
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

def bad_case_4(request: play.api.mvc.Request[AnyContent]): Unit = {
  val category = request.getQueryString("category").getOrElse("default")
  val minPrice = request.getQueryString("minPrice").getOrElse("0")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ruleid: scala-simple-db-query-injection
  val query = "SELECT * FROM products WHERE category = '" + category + "' AND price > " + minPrice
  val selectRequest = new SelectRequest(query)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

def bad_case_5(request: play.api.mvc.Request[AnyContent]): Unit = {
  val json = request.body.asJson.get
  val email = (json \ "email").as[String]
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ruleid: scala-simple-db-query-injection
  val selectRequest = new SelectRequest("SELECT * FROM customers WHERE email = '" + email + "'")
  val result = sdb.select(selectRequest)
}
// {/fact}

def bad_case_6()(implicit request: play.api.mvc.Request[AnyContent]): Unit = {
  val searchTerm = request.getQueryString("search").getOrElse("")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  val selectRequest = new SelectRequest()
  
  // ruleid: scala-simple-db-query-injection
  selectRequest.setSelectExpression(s"SELECT * FROM products WHERE name LIKE '%$searchTerm%'")
  val result = sdb.select(selectRequest)
}

def bad_case_7(request: akka.http.scaladsl.model.HttpRequest)(implicit ec: ExecutionContext): Future[Unit] = {
  import akka.http.scaladsl.unmarshalling.Unmarshal
  
  val futureQuery = request.entity.toStrict(5.seconds).flatMap { strict =>
    Unmarshal(strict).to[String]
  }
  
  futureQuery.map { query =>
    val sdb = AmazonSimpleDBClientBuilder.standard().build()
    // ruleid: scala-simple-db-query-injection
    val selectRequest = new SelectRequest(s"SELECT * FROM logs WHERE query = '$query'")
    val result = sdb.select(selectRequest)
  }
}
// {fact rule=nosql-injection@v1.0 defects=1}

def bad_case_8(request: play.api.mvc.Request[AnyContent]): Unit = {
  val orderId = request.cookies.get("orderId").map(_.value).getOrElse("")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ruleid: scala-simple-db-query-injection
  val query = "SELECT * FROM orders WHERE id = '" + orderId + "' LIMIT 1"
  val selectRequest = new SelectRequest(query)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

def bad_case_9(request: play.api.mvc.Request[AnyContent]): Unit = {
  val startDate = request.getQueryString("startDate").getOrElse("")
  val endDate = request.getQueryString("endDate").getOrElse("")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ruleid: scala-simple-db-query-injection
  val query = s"SELECT * FROM events WHERE date BETWEEN '$startDate' AND '$endDate'"
  val selectRequest = new SelectRequest(query)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

def bad_case_10(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userIds = request.body.asFormUrlEncoded.get("userIds").head.split(",")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // Constructing a query with user input
  val idList = userIds.map(id => s"'$id'").mkString(", ")
  // ruleid: scala-simple-db-query-injection
  val query = s"SELECT * FROM users WHERE id IN ($idList)"
  val selectRequest = new SelectRequest(query)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

def bad_case_11(request: play.api.mvc.Request[AnyContent]): Unit = {
  val sortField = request.getQueryString("sortField").getOrElse("name")
  val sortOrder = request.getQueryString("sortOrder").getOrElse("ASC")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ruleid: scala-simple-db-query-injection
  val query = s"SELECT * FROM products ORDER BY $sortField $sortOrder"
  val selectRequest = new SelectRequest(query)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

def bad_case_12(request: play.api.mvc.Request[AnyContent]): Unit = {
  val json = request.body.asJson.get
  val conditions = (json \ "conditions").as[String]
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ruleid: scala-simple-db-query-injection
  val query = s"SELECT * FROM data WHERE $conditions"
  val selectRequest = new SelectRequest(query)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

def bad_case_13(request: play.api.mvc.Request[AnyContent]): Unit = {
  val tableName = request.getQueryString("table").getOrElse("users")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ruleid: scala-simple-db-query-injection
  val query = s"SELECT * FROM $tableName"
  val selectRequest = new SelectRequest(query)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

def bad_case_14(request: play.api.mvc.Request[AnyContent]): Unit = {
  val attribute = request.getQueryString("attribute").getOrElse("name")
  val value = request.getQueryString("value").getOrElse("")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ruleid: scala-simple-db-query-injection
  val query = s"SELECT * FROM users WHERE $attribute = '$value'"
  val selectRequest = new SelectRequest(query)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

def bad_case_15(request: play.api.mvc.Request[AnyContent]): Unit = {
  val limit = request.getQueryString("limit").getOrElse("10")
  val offset = request.getQueryString("offset").getOrElse("0")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ruleid: scala-simple-db-query-injection
  val query = s"SELECT * FROM products LIMIT $limit OFFSET $offset"
  val selectRequest = new SelectRequest(query)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

// True negatives (safe code examples)

def good_case_1(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userId = request.getQueryString("userId").getOrElse("")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ok: scala-simple-db-query-injection
  val query = "SELECT * FROM users WHERE userId = ?"
  val selectRequest = new SelectRequest(query)
  selectRequest.withParams(userId)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

def good_case_2(request: play.api.mvc.Request[AnyContent]): Unit = {
  val username = request.body.asFormUrlEncoded.get("username").head
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ok: scala-simple-db-query-injection
  val selectRequest = new SelectRequest("SELECT * FROM users WHERE username = ?")
  selectRequest.withParams(username, "true")
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

def good_case_3(request: play.api.mvc.Request[AnyContent]): Unit = {
  val productId = request.headers.get("X-Product-Id").getOrElse("")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // Validate input before using
  val sanitizedProductId = productId.replaceAll("[^a-zA-Z0-9]", "")
  
  // ok: scala-simple-db-query-injection
  val selectRequest = new SelectRequest()
  selectRequest.setSelectExpression(s"SELECT * FROM products WHERE productId = '$sanitizedProductId'")
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

def good_case_4(request: play.api.mvc.Request[AnyContent]): Unit = {
  val category = request.getQueryString("category").getOrElse("default")
  val minPriceStr = request.getQueryString("minPrice").getOrElse("0")
  
  // Validate input
  val validCategories = Set("electronics", "books", "clothing")
  val safeCategory = if (validCategories.contains(category)) category else "default"
  
  val minPrice = try {
    minPriceStr.toInt
  } catch {
    case _: NumberFormatException => 0
  }
  
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ok: scala-simple-db-query-injection
  val selectRequest = new SelectRequest()
  selectRequest.setSelectExpression(s"SELECT * FROM products WHERE category = '$safeCategory' AND price > $minPrice")
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

def good_case_5(request: play.api.mvc.Request[AnyContent]): Unit = {
  val json = request.body.asJson.get
  val email = (json \ "email").as[String]
  
  // Validate email format
  val emailRegex = """^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$""".r
  val isValidEmail = emailRegex.findFirstMatchIn(email).isDefined
  
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  if (isValidEmail) {
    // ok: scala-simple-db-query-injection
    val selectRequest = new SelectRequest()
    selectRequest.setSelectExpression("SELECT * FROM customers WHERE email = ?")
    selectRequest.withParams(email)
    val result = sdb.select(selectRequest)
  } else {
    throw new IllegalArgumentException("Invalid email format")
  }
}
// {/fact}

def good_case_6()(implicit request: play.api.mvc.Request[AnyContent]): Unit = {
  val searchTerm = request.getQueryString("search").getOrElse("")
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ok: scala-simple-db-query-injection
  val selectRequest = new SelectRequest()
  selectRequest.setSelectExpression("SELECT * FROM products WHERE name LIKE ?")
  selectRequest.withParams(s"%$searchTerm%")
  val result = sdb.select(selectRequest)
}

def good_case_7(request: akka.http.scaladsl.model.HttpRequest)(implicit ec: ExecutionContext): Future[Unit] = {
  import akka.http.scaladsl.unmarshalling.Unmarshal
  
  val futureQuery = request.entity.toStrict(5.seconds).flatMap { strict =>
    Unmarshal(strict).to[String]
  }
  
  futureQuery.map { query =>
    val sdb = AmazonSimpleDBClientBuilder.standard().build()
    // ok: scala-simple-db-query-injection
    val selectRequest = new SelectRequest()
    selectRequest.setSelectExpression("SELECT * FROM logs WHERE query = ?")
    selectRequest.withParams(query)
    val result = sdb.select(selectRequest)
  }
}
// {fact rule=nosql-injection@v1.0 defects=0}

def good_case_8(request: play.api.mvc.Request[AnyContent]): Unit = {
  val orderId = request.cookies.get("orderId").map(_.value).getOrElse("")
  
  // Validate orderId format (assuming it should be alphanumeric)
  if (!orderId.matches("[a-zA-Z0-9]+")) {
    throw new IllegalArgumentException("Invalid order ID format")
  }
  
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ok: scala-simple-db-query-injection
  val selectRequest = new SelectRequest()
  selectRequest.setSelectExpression("SELECT * FROM orders WHERE id = ? LIMIT 1")
  selectRequest.withParams(orderId)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

def good_case_9(request: play.api.mvc.Request[AnyContent]): Unit = {
  val startDate = request.getQueryString("startDate").getOrElse("")
  val endDate = request.getQueryString("endDate").getOrElse("")
  
  // Validate date format
  val dateFormat = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd")
  try {
    if (!startDate.isEmpty) java.time.LocalDate.parse(startDate, dateFormat)
    if (!endDate.isEmpty) java.time.LocalDate.parse(endDate, dateFormat)
  } catch {
    case _: Exception => throw new IllegalArgumentException("Invalid date format")
  }
  
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ok: scala-simple-db-query-injection
  val selectRequest = new SelectRequest()
  selectRequest.setSelectExpression("SELECT * FROM events WHERE date BETWEEN ? AND ?")
  selectRequest.withParams(startDate, endDate)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

def good_case_10(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userIdsRaw = request.body.asFormUrlEncoded.get("userIds").head.split(",")
  
  // Validate each user ID
  val userIds = userIdsRaw.filter(_.matches("[a-zA-Z0-9]+"))
  
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ok: scala-simple-db-query-injection
  val placeholders = userIds.map(_ => "?").mkString(", ")
  val selectRequest = new SelectRequest()
  selectRequest.setSelectExpression(s"SELECT * FROM users WHERE id IN ($placeholders)")
  selectRequest.withParams(userIds: _*)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

def good_case_11(request: play.api.mvc.Request[AnyContent]): Unit = {
  val sortFieldRaw = request.getQueryString("sortField").getOrElse("name")
  val sortOrderRaw = request.getQueryString("sortOrder").getOrElse("ASC")
  
  // Whitelist validation
  val allowedFields = Set("name", "price", "date")
  val sortField = if (allowedFields.contains(sortFieldRaw)) sortFieldRaw else "name"
  
  val allowedOrders = Set("ASC", "DESC")
  val sortOrder = if (allowedOrders.contains(sortOrderRaw)) sortOrderRaw else "ASC"
  
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ok: scala-simple-db-query-injection
  val selectRequest = new SelectRequest()
  selectRequest.setSelectExpression(s"SELECT * FROM products ORDER BY $sortField $sortOrder")
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

def good_case_12(request: play.api.mvc.Request[AnyContent]): Unit = {
  val json = request.body.asJson.get
  val field = (json \ "field").as[String]
  val value = (json \ "value").as[String]
  
  // Whitelist validation for field
  val allowedFields = Set("name", "email", "status")
  if (!allowedFields.contains(field)) {
    throw new IllegalArgumentException("Invalid field")
  }
  
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ok: scala-simple-db-query-injection
  val selectRequest = new SelectRequest()
  selectRequest.setSelectExpression(s"SELECT * FROM data WHERE $field = ?")
  selectRequest.withParams(value)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

def good_case_13(request: play.api.mvc.Request[AnyContent]): Unit = {
  val tableNameRaw = request.getQueryString("table").getOrElse("users")
  
  // Whitelist validation
  val allowedTables = Map(
    "users" -> "users",
    "products" -> "products",
    "orders" -> "orders"
  )
  
  val tableName = allowedTables.getOrElse(tableNameRaw, "users")
  
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ok: scala-simple-db-query-injection
  val selectRequest = new SelectRequest()
  selectRequest.setSelectExpression(s"SELECT * FROM $tableName")
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

def good_case_14(request: play.api.mvc.Request[AnyContent]): Unit = {
  val attributeRaw = request.getQueryString("attribute").getOrElse("name")
  val value = request.getQueryString("value").getOrElse("")
  
  // Whitelist validation
  val allowedAttributes = Set("name", "email", "status")
  if (!allowedAttributes.contains(attributeRaw)) {
    throw new IllegalArgumentException("Invalid attribute")
  }
  
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ok: scala-simple-db-query-injection
  val selectRequest = new SelectRequest()
  selectRequest.setSelectExpression(s"SELECT * FROM users WHERE $attributeRaw = ?")
  selectRequest.withParams(value)
  val result = sdb.select(selectRequest)
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

def good_case_15(request: play.api.mvc.Request[AnyContent]): Unit = {
  val limitRaw = request.getQueryString("limit").getOrElse("10")
  val offsetRaw = request.getQueryString("offset").getOrElse("0")
  
  // Parse and validate numeric values
  val limit = try {
    val l = limitRaw.toInt
    if (l > 0 && l <= 100) l else 10  // Enforce reasonable limits
  } catch {
    case _: NumberFormatException => 10
  }
  
  val offset = try {
    val o = offsetRaw.toInt
    if (o >= 0) o else 0
  } catch {
    case _: NumberFormatException => 0
  }
  
  val sdb = AmazonSimpleDBClientBuilder.standard().build()
  
  // ok: scala-simple-db-query-injection
  val selectRequest = new SelectRequest()
  selectRequest.setSelectExpression(s"SELECT * FROM products LIMIT $limit OFFSET $offset")
  val result = sdb.select(selectRequest)
}
// {/fact}