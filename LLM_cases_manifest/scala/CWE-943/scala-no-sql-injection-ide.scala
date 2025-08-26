import scala.concurrent.{Future, ExecutionContext}
import scala.concurrent.ExecutionContext.Implicits.global
import play.api.mvc._
import play.api.libs.json._
import org.mongodb.scala._
import org.mongodb.scala.model.Filters
import org.mongodb.scala.bson._
import reactivemongo.api._
import reactivemongo.api.bson._
import reactivemongo.api.commands.WriteResult
import reactivemongo.play.json.collection.JSONCollection
import java.util.regex.Pattern
import javax.inject.Inject
import cats.data.Validated
import cats.data.ValidatedNel
import cats.implicits._

// True Positive Examples (Vulnerable Code)

def bad_case_1(request: Request[AnyContent]): Future[Option[Document]] = {
  val username = request.getQueryString("username").getOrElse("")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("test").getCollection("users")
  
  // ruleid: scala-no-sql-injection-ide
  val query = s"""{ "username": "$username" }"""
  collection.find(Document(query)).first().toFuture()
}

def bad_case_2(request: Request[AnyContent]): Future[Seq[Document]] = {
  val searchTerm = request.getQueryString("search").getOrElse("")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("products").getCollection("items")
  
  // ruleid: scala-no-sql-injection-ide
  val queryString = s"""{ "description": { "$$regex": "$searchTerm" } }"""
  collection.find(Document(queryString)).toFuture()
}

def bad_case_3(request: Request[AnyContent]): Future[DeleteResult] = {
  val userId = request.getQueryString("id").getOrElse("")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("users").getCollection("profiles")
  
  // ruleid: scala-no-sql-injection-ide
  val deleteQuery = s"""{ "_id": "$userId" }"""
  collection.deleteOne(Document(deleteQuery)).toFuture()
}

def bad_case_4(request: Request[AnyContent]): Future[Seq[Document]] = {
  val field = request.getQueryString("field").getOrElse("name")
  val value = request.getQueryString("value").getOrElse("")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("test").getCollection("customers")
  
  // ruleid: scala-no-sql-injection-ide
  val dynamicQuery = s"""{ "$field": "$value" }"""
  collection.find(Document(dynamicQuery)).toFuture()
}

def bad_case_5(request: Request[AnyContent]): Future[UpdateResult] = {
  val username = request.getQueryString("username").getOrElse("")
  val newRole = request.getQueryString("role").getOrElse("user")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("app").getCollection("users")
  
  // ruleid: scala-no-sql-injection-ide
  val query = s"""{ "username": "$username" }"""
  val update = s"""{ "$$set": { "role": "$newRole" } }"""
  collection.updateOne(Document(query), Document(update)).toFuture()
}

def bad_case_6(request: Request[AnyContent])(implicit ec: ExecutionContext): Future[Option[JsObject]] = {
  val db: Future[DefaultDB] = MongoConnection.fromURI("mongodb://localhost:27017").flatMap(_.database("test"))
  val username = request.getQueryString("username").getOrElse("")
  val password = request.getQueryString("password").getOrElse("")
  
  db.flatMap { database =>
    val collection = database.collection[JSONCollection]("users")
    // ruleid: scala-no-sql-injection-ide
    val selector = Json.obj("username" -> username, "password" -> Json.obj("$ne" -> password))
    collection.find(selector).one[JsObject]
  }
}

def bad_case_7(request: Request[AnyContent]): Future[Seq[Document]] = {
  val minAge = request.getQueryString("minAge").getOrElse("18")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("users").getCollection("profiles")
  
  // ruleid: scala-no-sql-injection-ide
  val query = s"""{ "age": { "$$gte": $minAge } }"""
  collection.find(Document(query)).toFuture()
}

def bad_case_8(request: Request[AnyContent])(implicit ec: ExecutionContext): Future[List[BSONDocument]] = {
  val db: Future[DefaultDB] = MongoConnection.fromURI("mongodb://localhost:27017").flatMap(_.database("test"))
  val searchPattern = request.getQueryString("pattern").getOrElse("")
  
  db.flatMap { database =>
    val collection = database.collection[BSONCollection]("products")
    // ruleid: scala-no-sql-injection-ide
    val query = BSONDocument("name" -> BSONDocument("$regex" -> searchPattern))
    collection.find(query).cursor[BSONDocument]().collect[List](10)
  }
}

def bad_case_9(request: Request[AnyContent]): Future[Seq[Document]] = {
  val sortField = request.getQueryString("sortBy").getOrElse("name")
  val sortOrder = request.getQueryString("order").getOrElse("1")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("store").getCollection("products")
  
  // ruleid: scala-no-sql-injection-ide
  val sort = s"""{ "$sortField": $sortOrder }"""
  collection.find().sort(Document(sort)).toFuture()
}

def bad_case_10(request: Request[AnyContent]): Future[Seq[Document]] = {
  val category = request.getQueryString("category").getOrElse("")
  val maxPrice = request.getQueryString("maxPrice").getOrElse("100")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("store").getCollection("products")
  
  // ruleid: scala-no-sql-injection-ide
  val query = s"""{ "category": "$category", "price": { "$$lte": $maxPrice } }"""
  collection.find(Document(query)).toFuture()
}

def bad_case_11(request: Request[AnyContent])(implicit ec: ExecutionContext): Future[Option[JsObject]] = {
  val db: Future[DefaultDB] = MongoConnection.fromURI("mongodb://localhost:27017").flatMap(_.database("test"))
  val email = request.getQueryString("email").getOrElse("")
  
  db.flatMap { database =>
    val collection = database.collection[JSONCollection]("users")
    // ruleid: scala-no-sql-injection-ide
    val selector = Json.parse(s"""{ "email": { "$$regex": "$email", "$$options": "i" } }""").as[JsObject]
    collection.find(selector).one[JsObject]
  }
}

def bad_case_12(request: Request[AnyContent]): Future[Seq[Document]] = {
  val tags = request.getQueryString("tags").getOrElse("")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("blog").getCollection("posts")
  
  // ruleid: scala-no-sql-injection-ide
  val query = s"""{ "tags": { "$$in": [$tags] } }"""
  collection.find(Document(query)).toFuture()
}

def bad_case_13(request: Request[AnyContent]): Future[UpdateResult] = {
  val id = request.getQueryString("id").getOrElse("")
  val status = request.getQueryString("status").getOrElse("active")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("orders").getCollection("shipments")
  
  // ruleid: scala-no-sql-injection-ide
  val filter = s"""{ "_id": "$id" }"""
  val update = s"""{ "$$set": { "status": "$status" } }"""
  collection.updateOne(Document(filter), Document(update)).toFuture()
}

def bad_case_14(request: Request[AnyContent])(implicit ec: ExecutionContext): Future[WriteResult] = {
  val db: Future[DefaultDB] = MongoConnection.fromURI("mongodb://localhost:27017").flatMap(_.database("test"))
  val username = request.getQueryString("username").getOrElse("")
  
  db.flatMap { database =>
    val collection = database.collection[BSONCollection]("users")
    // ruleid: scala-no-sql-injection-ide
    val selector = BSONDocument("username" -> BSONDocument("$eq" -> username))
    collection.delete().one(selector)
  }
}

def bad_case_15(request: Request[AnyContent]): Future[Seq[Document]] = {
  val field = request.getQueryString("field").getOrElse("title")
  val keywords = request.getQueryString("keywords").getOrElse("")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("content").getCollection("articles")
  
  // ruleid: scala-no-sql-injection-ide
  val query = s"""{ "$field": { "$$text": { "$$search": "$keywords" } } }"""
  collection.find(Document(query)).toFuture()
}

// True Negative Examples (Secure Code)

def good_case_1(request: Request[AnyContent]): Future[Option[Document]] = {
  val username = request.getQueryString("username").getOrElse("")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("test").getCollection("users")
  
  // ok: scala-no-sql-injection-ide
  collection.find(Filters.eq("username", username)).first().toFuture()
}

def good_case_2(request: Request[AnyContent]): Future[Seq[Document]] = {
  val searchTerm = request.getQueryString("search").getOrElse("")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("products").getCollection("items")
  
  // ok: scala-no-sql-injection-ide
  val sanitizedTerm = Pattern.quote(searchTerm)
  collection.find(Filters.regex("description", sanitizedTerm)).toFuture()
}

def good_case_3(request: Request[AnyContent]): Future[DeleteResult] = {
  val userId = request.getQueryString("id").getOrElse("")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("users").getCollection("profiles")
  
  // ok: scala-no-sql-injection-ide
  collection.deleteOne(Filters.eq("_id", userId)).toFuture()
}

def good_case_4(request: Request[AnyContent]): Future[Seq[Document]] = {
  val value = request.getQueryString("value").getOrElse("")
  val field = request.getQueryString("field").getOrElse("name")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("test").getCollection("customers")
  
  // Validate field against allowlist
  val allowedFields = Set("name", "email", "phone")
  val safeField = if (allowedFields.contains(field)) field else "name"
  
  // ok: scala-no-sql-injection-ide
  collection.find(Filters.eq(safeField, value)).toFuture()
}

def good_case_5(request: Request[AnyContent]): Future[UpdateResult] = {
  val username = request.getQueryString("username").getOrElse("")
  val newRole = request.getQueryString("role").getOrElse("user")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("app").getCollection("users")
  
  // Validate role against allowlist
  val allowedRoles = Set("user", "editor", "viewer")
  val safeRole = if (allowedRoles.contains(newRole)) newRole else "user"
  
  // ok: scala-no-sql-injection-ide
  collection.updateOne(Filters.eq("username", username), 
                      Document("$set", Document("role", safeRole))).toFuture()
}

def good_case_6(request: Request[AnyContent])(implicit ec: ExecutionContext): Future[Option[JsObject]] = {
  val db: Future[DefaultDB] = MongoConnection.fromURI("mongodb://localhost:27017").flatMap(_.database("test"))
  val username = request.getQueryString("username").getOrElse("")
  val password = request.getQueryString("password").getOrElse("")
  
  db.flatMap { database =>
    val collection = database.collection[JSONCollection]("users")
    // ok: scala-no-sql-injection-ide
    val selector = Json.obj("username" -> username, "password" -> password)
    collection.find(selector).one[JsObject]
  }
}

def good_case_7(request: Request[AnyContent]): Future[Seq[Document]] = {
  val minAgeStr = request.getQueryString("minAge").getOrElse("18")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("users").getCollection("profiles")
  
  // Parse and validate the age parameter
  val minAge = try {
    minAgeStr.toInt
  } catch {
    case _: NumberFormatException => 18 // Default value if parsing fails
  }
  
  // ok: scala-no-sql-injection-ide
  collection.find(Filters.gte("age", minAge)).toFuture()
}

def good_case_8(request: Request[AnyContent])(implicit ec: ExecutionContext): Future[List[BSONDocument]] = {
  val db: Future[DefaultDB] = MongoConnection.fromURI("mongodb://localhost:27017").flatMap(_.database("test"))
  val searchPattern = request.getQueryString("pattern").getOrElse("")
  
  db.flatMap { database =>
    val collection = database.collection[BSONCollection]("products")
    // ok: scala-no-sql-injection-ide
    val sanitizedPattern = Pattern.quote(searchPattern)
    val query = BSONDocument("name" -> BSONDocument("$regex" -> sanitizedPattern))
    collection.find(query).cursor[BSONDocument]().collect[List](10)
  }
}

def good_case_9(request: Request[AnyContent]): Future[Seq[Document]] = {
  val sortFieldInput = request.getQueryString("sortBy").getOrElse("name")
  val sortOrderInput = request.getQueryString("order").getOrElse("1")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("store").getCollection("products")
  
  // Validate sort field against allowlist
  val allowedSortFields = Set("name", "price", "date")
  val sortField = if (allowedSortFields.contains(sortFieldInput)) sortFieldInput else "name"
  
  // Validate sort order
  val sortOrder = if (sortOrderInput == "-1") -1 else 1
  
  // ok: scala-no-sql-injection-ide
  collection.find().sort(Document(sortField -> sortOrder)).toFuture()
}

def good_case_10(request: Request[AnyContent]): Future[Seq[Document]] = {
  val category = request.getQueryString("category").getOrElse("")
  val maxPriceStr = request.getQueryString("maxPrice").getOrElse("100")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("store").getCollection("products")
  
  // Parse and validate the price parameter
  val maxPrice = try {
    maxPriceStr.toDouble
  } catch {
    case _: NumberFormatException => 100.0 // Default value if parsing fails
  }
  
  // ok: scala-no-sql-injection-ide
  import org.mongodb.scala.model.Filters._
  val query = and(equal("category", category), lte("price", maxPrice))
  collection.find(query).toFuture()
}

def good_case_11(request: Request[AnyContent])(implicit ec: ExecutionContext): Future[Option[JsObject]] = {
  val db: Future[DefaultDB] = MongoConnection.fromURI("mongodb://localhost:27017").flatMap(_.database("test"))
  val email = request.getQueryString("email").getOrElse("")
  
  db.flatMap { database =>
    val collection = database.collection[JSONCollection]("users")
    // ok: scala-no-sql-injection-ide
    val sanitizedEmail = Pattern.quote(email)
    val selector = Json.obj("email" -> Json.obj("$regex" -> sanitizedEmail, "$options" -> "i"))
    collection.find(selector).one[JsObject]
  }
}

def good_case_12(request: Request[AnyContent]): Future[Seq[Document]] = {
  val tagsInput = request.getQueryString("tags").getOrElse("")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("blog").getCollection("posts")
  
  // Parse and sanitize tags
  val tags = tagsInput.split(",").map(_.trim).filter(_.nonEmpty).toList
  
  // ok: scala-no-sql-injection-ide
  collection.find(Filters.in("tags", tags:_*)).toFuture()
}

def good_case_13(request: Request[AnyContent]): Future[UpdateResult] = {
  val id = request.getQueryString("id").getOrElse("")
  val statusInput = request.getQueryString("status").getOrElse("active")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("orders").getCollection("shipments")
  
  // Validate status against allowlist
  val allowedStatuses = Set("active", "pending", "shipped", "delivered")
  val status = if (allowedStatuses.contains(statusInput)) statusInput else "pending"
  
  // ok: scala-no-sql-injection-ide
  collection.updateOne(Filters.eq("_id", id), 
                      Document("$set", Document("status", status))).toFuture()
}

def good_case_14(request: Request[AnyContent])(implicit ec: ExecutionContext): Future[WriteResult] = {
  val db: Future[DefaultDB] = MongoConnection.fromURI("mongodb://localhost:27017").flatMap(_.database("test"))
  val username = request.getQueryString("username").getOrElse("")
  
  // Validate username format using Cats Validate
  val usernameValidator: String => ValidatedNel[String, String] = input => 
    if (input.matches("^[a-zA-Z0-9_]{3,20}$")) input.validNel
    else "Invalid username format".invalidNel
  
  val validatedUsername = usernameValidator(username)
  
  db.flatMap { database =>
    val collection = database.collection[BSONCollection]("users")
    validatedUsername match {
      case Validated.Valid(validUsername) =>
        // ok: scala-no-sql-injection-ide
        collection.delete().one(BSONDocument("username" -> validUsername))
      case Validated.Invalid(_) =>
        Future.successful(WriteResult.empty)
    }
  }
}

def good_case_15(request: Request[AnyContent]): Future[Seq[Document]] = {
  val fieldInput = request.getQueryString("field").getOrElse("title")
  val keywords = request.getQueryString("keywords").getOrElse("")
  val collection = MongoClient("mongodb://localhost:27017").getDatabase("content").getCollection("articles")
  
  // Validate field against allowlist
  val allowedFields = Set("title", "content", "tags")
  val field = if (allowedFields.contains(fieldInput)) fieldInput else "title"
  
  // ok: scala-no-sql-injection-ide
  val sanitizedKeywords = Pattern.quote(keywords)
  collection.find(Filters.regex(field, sanitizedKeywords)).toFuture()
}