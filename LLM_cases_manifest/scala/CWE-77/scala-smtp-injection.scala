import javax.mail._
import javax.mail.internet._
import java.util.Properties
import org.apache.commons.lang3.StringEscapeUtils
import play.api.mvc._
import play.api.http._
import scala.io.Source
import scala.util.control.Exception._
import org.apache.commons.text.StringEscapeUtils
import play.api.libs.json._
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

def bad_case_1(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.getQueryString("subject").getOrElse("")
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  // ruleid: scala-smtp-injection
  message.setSubject(userInput)
  
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_2(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.body.asFormUrlEncoded.get("recipient")(0)
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  // ruleid: scala-smtp-injection
  message.addRecipient(Message.RecipientType.TO, new InternetAddress(userInput))
  
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_3(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.body.asJson.get("message").as[String]
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  // ruleid: scala-smtp-injection
  message.setText(userInput)
  
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_4(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.headers.get("X-Custom-Header").getOrElse("")
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  // ruleid: scala-smtp-injection
  message.addHeader("X-Custom", userInput)
  
  message.setSubject("Hello")
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_5(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.cookies.get("user_preference").map(_.value).getOrElse("")
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  // ruleid: scala-smtp-injection
  val content = s"<html><body><h1>Welcome</h1><p>${userInput}</p></body></html>"
  message.setContent(content, "text/html")
  
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_6(request: play.api.mvc.Request[AnyContent]): Unit = {
  val fromAddress = request.getQueryString("from").getOrElse("default@example.com")
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  // ruleid: scala-smtp-injection
  message.setFrom(new InternetAddress(fromAddress))
  
  message.setSubject("Hello")
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_7(request: play.api.mvc.Request[AnyContent]): Unit = {
  val ccRecipient = request.body.asFormUrlEncoded.get("cc")(0)
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  // ruleid: scala-smtp-injection
  message.addRecipient(Message.RecipientType.CC, new InternetAddress(ccRecipient))
  
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_8(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.body.asJson.get("replyTo").as[String]
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  
  // ruleid: scala-smtp-injection
  message.setReplyTo(Array(new InternetAddress(userInput)))
  
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_9(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.getQueryString("content-type").getOrElse("text/plain")
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  val content = "This is the message body"
  // ruleid: scala-smtp-injection
  message.setContent(content, userInput)
  
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_10(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.body.asFormUrlEncoded.get("bcc")(0)
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  // ruleid: scala-smtp-injection
  message.addRecipient(Message.RecipientType.BCC, new InternetAddress(userInput))
  
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_11(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.body.asJson.get("subject").as[String]
  val messageBody = request.body.asJson.get("body").as[String]
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  // ruleid: scala-smtp-injection
  message.setSubject(userInput)
  
  // ruleid: scala-smtp-injection
  message.setText(messageBody)
  
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_12(request: play.api.mvc.Request[AnyContent]): Unit = {
  val headerName = request.getQueryString("header-name").getOrElse("X-Custom")
  val headerValue = request.getQueryString("header-value").getOrElse("")
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  // ruleid: scala-smtp-injection
  message.addHeader(headerName, headerValue)
  
  message.setSubject("Hello")
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_13(request: play.api.mvc.Request[AnyContent]): Unit = {
  val recipients = request.body.asJson.get("recipients").as[List[String]]
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  
  for (recipient <- recipients) {
    // ruleid: scala-smtp-injection
    message.addRecipient(Message.RecipientType.TO, new InternetAddress(recipient))
  }
  
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_14(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.body.asJson.get("content").as[String]
  val contentType = request.body.asJson.get("contentType").as[String]
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  // ruleid: scala-smtp-injection
  message.setContent(userInput, contentType)
  
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

def bad_case_15(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.getQueryString("description").getOrElse("")
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  val bodyPart = new MimeBodyPart()
  // ruleid: scala-smtp-injection
  bodyPart.setDescription(userInput)
  
  val multipart = new MimeMultipart()
  multipart.addBodyPart(bodyPart)
  
  message.setContent(multipart)
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

// True Negative Examples (Safe Code)

def good_case_1(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.getQueryString("subject").getOrElse("")
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  // ok: scala-smtp-injection
  message.setSubject(StringEscapeUtils.escapeJava(userInput))
  
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_2(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.body.asFormUrlEncoded.get("recipient")(0)
  
  // Input validation for email format
  val emailRegex = """^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$""".r
  
  if (emailRegex.findFirstMatchIn(userInput).isDefined) {
    val props = new Properties()
    props.put("mail.smtp.host", "smtp.example.com")
    
    val session = Session.getDefaultInstance(props, null)
    val message = new MimeMessage(session)
    
    message.setSubject("Hello")
    // ok: scala-smtp-injection
    message.addRecipient(Message.RecipientType.TO, new InternetAddress(userInput))
    
    message.setText("This is the message body")
    Transport.send(message)
  } else {
    // Handle invalid email format
    println("Invalid email format")
  }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_3(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.body.asJson.get("message").as[String]
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  // ok: scala-smtp-injection
  message.setText(StringEscapeUtils.escapeJava(userInput))
  
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_4(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.headers.get("X-Custom-Header").getOrElse("")
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  // ok: scala-smtp-injection
  message.addHeader("X-Custom", StringEscapeUtils.escapeJava(userInput))
  
  message.setSubject("Hello")
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_5(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.cookies.get("user_preference").map(_.value).getOrElse("")
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  // ok: scala-smtp-injection
  val sanitizedInput = org.apache.commons.text.StringEscapeUtils.escapeHtml4(userInput)
  val content = s"<html><body><h1>Welcome</h1><p>${sanitizedInput}</p></body></html>"
  message.setContent(content, "text/html")
  
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_6(request: play.api.mvc.Request[AnyContent]): Unit = {
  val fromAddress = request.getQueryString("from").getOrElse("default@example.com")
  
  // Input validation for email format
  val emailRegex = """^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$""".r
  
  if (emailRegex.findFirstMatchIn(fromAddress).isDefined) {
    val props = new Properties()
    props.put("mail.smtp.host", "smtp.example.com")
    
    val session = Session.getDefaultInstance(props, null)
    val message = new MimeMessage(session)
    
    // ok: scala-smtp-injection
    message.setFrom(new InternetAddress(fromAddress))
    
    message.setSubject("Hello")
    message.setText("This is the message body")
    Transport.send(message)
  } else {
    // Handle invalid email format
    println("Invalid email format")
  }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_7(request: play.api.mvc.Request[AnyContent]): Unit = {
  // Using a whitelist approach for CC recipients
  val allowedCCRecipients = Set("manager@example.com", "support@example.com", "info@example.com")
  val ccRecipient = request.body.asFormUrlEncoded.get("cc")(0)
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  // ok: scala-smtp-injection
  if (allowedCCRecipients.contains(ccRecipient)) {
    message.addRecipient(Message.RecipientType.CC, new InternetAddress(ccRecipient))
  }
  
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_8(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.body.asJson.get("replyTo").as[String]
  
  // Input validation for email format
  val emailRegex = """^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$""".r
  
  if (emailRegex.findFirstMatchIn(userInput).isDefined) {
    val props = new Properties()
    props.put("mail.smtp.host", "smtp.example.com")
    
    val session = Session.getDefaultInstance(props, null)
    val message = new MimeMessage(session)
    
    message.setSubject("Hello")
    
    // ok: scala-smtp-injection
    message.setReplyTo(Array(new InternetAddress(userInput)))
    
    message.setText("This is the message body")
    Transport.send(message)
  } else {
    // Handle invalid email format
    println("Invalid email format")
  }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_9(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.getQueryString("content-type").getOrElse("text/plain")
  
  // Whitelist approach for content types
  val allowedContentTypes = Set("text/plain", "text/html", "text/xml", "application/json")
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  val content = "This is the message body"
  // ok: scala-smtp-injection
  if (allowedContentTypes.contains(userInput)) {
    message.setContent(content, userInput)
  } else {
    message.setContent(content, "text/plain") // Default to text/plain if not in whitelist
  }
  
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_10(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.body.asFormUrlEncoded.get("bcc")(0)
  
  // Input validation for email format
  val emailRegex = """^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$""".r
  
  if (emailRegex.findFirstMatchIn(userInput).isDefined) {
    val props = new Properties()
    props.put("mail.smtp.host", "smtp.example.com")
    
    val session = Session.getDefaultInstance(props, null)
    val message = new MimeMessage(session)
    
    message.setSubject("Hello")
    message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
    
    // ok: scala-smtp-injection
    message.addRecipient(Message.RecipientType.BCC, new InternetAddress(userInput))
    
    message.setText("This is the message body")
    Transport.send(message)
  } else {
    // Handle invalid email format
    println("Invalid email format")
  }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_11(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.body.asJson.get("subject").as[String]
  val messageBody = request.body.asJson.get("body").as[String]
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  // ok: scala-smtp-injection
  message.setSubject(StringEscapeUtils.escapeJava(userInput))
  
  // ok: scala-smtp-injection
  message.setText(StringEscapeUtils.escapeJava(messageBody))
  
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_12(request: play.api.mvc.Request[AnyContent]): Unit = {
  val headerValue = request.getQueryString("header-value").getOrElse("")
  
  // Using a fixed header name instead of user input
  val headerName = "X-Custom"
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  // ok: scala-smtp-injection
  message.addHeader(headerName, StringEscapeUtils.escapeJava(headerValue))
  
  message.setSubject("Hello")
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_13(request: play.api.mvc.Request[AnyContent]): Unit = {
  val recipients = request.body.asJson.get("recipients").as[List[String]]
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  
  // Email format validation
  val emailRegex = """^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$""".r
  
  for (recipient <- recipients) {
    // ok: scala-smtp-injection
    if (emailRegex.findFirstMatchIn(recipient).isDefined) {
      message.addRecipient(Message.RecipientType.TO, new InternetAddress(recipient))
    }
  }
  
  message.setText("This is the message body")
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_14(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.body.asJson.get("content").as[String]
  
  // Fixed content type instead of user input
  val contentType = "text/html"
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  // ok: scala-smtp-injection
  val sanitizedContent = org.apache.commons.text.StringEscapeUtils.escapeHtml4(userInput)
  message.setContent(sanitizedContent, contentType)
  
  Transport.send(message)
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

def good_case_15(request: play.api.mvc.Request[AnyContent]): Unit = {
  val userInput = request.getQueryString("description").getOrElse("")
  
  val props = new Properties()
  props.put("mail.smtp.host", "smtp.example.com")
  
  val session = Session.getDefaultInstance(props, null)
  val message = new MimeMessage(session)
  
  message.setSubject("Hello")
  message.addRecipient(Message.RecipientType.TO, new InternetAddress("recipient@example.com"))
  
  val bodyPart = new MimeBodyPart()
  // ok: scala-smtp-injection
  bodyPart.setDescription(StringEscapeUtils.escapeJava(userInput))
  
  val multipart = new MimeMultipart()
  multipart.addBodyPart(bodyPart)
  
  message.setContent(multipart)
  Transport.send(message)
}
// {/fact}