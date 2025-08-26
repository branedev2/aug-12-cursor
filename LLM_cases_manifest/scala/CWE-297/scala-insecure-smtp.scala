import javax.mail._
import javax.mail.internet._
import java.util.Properties
import org.apache.commons.mail._
import org.apache.commons.mail.Email
import org.apache.commons.mail.SimpleEmail
import org.apache.commons.mail.EmailException
import org.apache.commons.mail.HtmlEmail
import org.apache.commons.mail.MultiPartEmail
import org.apache.commons.mail.ImageHtmlEmail
import scala.util.Try
import scala.util.Success
import scala.util.Failure
import com.typesafe.config.ConfigFactory
import java.io.FileInputStream
import java.util.Properties
import scala.io.Source
import scala.collection.JavaConverters._
import java.nio.file.{Files, Paths}

object SMTPSecurityExamples {

  // True Positive Examples (Vulnerable Code)

  def bad_case_1(): Unit = {
    val email = new SimpleEmail()
    email.setHostName("smtp.example.com")
    email.setSmtpPort(465)
    email.setAuthentication("username", "password")
    // ruleid: scala-insecure-smtp
    email.setSSLOnConnect(true)
    email.setFrom("user@example.com")
    email.setSubject("Test Subject")
    email.setMsg("Test Message")
    email.addTo("recipient@example.com")
    email.send()
  }

  def bad_case_2(): Unit = {
    val email = new HtmlEmail()
    email.setHostName("smtp.example.com")
    email.setSmtpPort(587)
    // ruleid: scala-insecure-smtp
    email.setSSLOnConnect(true)
    email.setAuthentication("username", "password123")
    email.setFrom("sender@example.com")
    email.setSubject("HTML Email Test")
    email.setHtmlMsg("<html><body><h1>Test HTML Message</h1></body></html>")
    email.addTo("recipient@example.com")
    email.send()
  }

  def bad_case_3(): Unit = {
    try {
      val email = new MultiPartEmail()
      email.setHostName("smtp.gmail.com")
      // ruleid: scala-insecure-smtp
      email.setSSLOnConnect(true)
      email.setSmtpPort(465)
      email.setAuthentication("user@gmail.com", "gmailPassword")
      email.setFrom("user@gmail.com", "Sender Name")
      email.addTo("recipient@example.com")
      email.setSubject("Multipart Email Test")
      email.setMsg("This is a test multipart email")
      email.send()
    } catch {
      case e: EmailException => println(s"Error sending email: ${e.getMessage}")
    }
  }

  def bad_case_4(): Unit = {
    val config = ConfigFactory.load()
    val email = new SimpleEmail()
    email.setHostName(config.getString("smtp.host"))
    email.setSmtpPort(config.getInt("smtp.port"))
    email.setAuthentication(config.getString("smtp.username"), config.getString("smtp.password"))
    // ruleid: scala-insecure-smtp
    email.setSSLOnConnect(true)
    email.setFrom(config.getString("smtp.from"))
    email.setSubject("Configuration-based Email")
    email.setMsg("Email with configuration")
    email.addTo(config.getString("smtp.recipient"))
    email.send()
  }

  def bad_case_5(): Unit = {
    val email = new ImageHtmlEmail()
    // Setting up the mail server
    email.setHostName("mail.server.com")
    email.setSmtpPort(587)
    email.setAuthentication("username", "password")
    // ruleid: scala-insecure-smtp
    email.setSSLOnConnect(true)
    email.setFrom("user@example.com")
    email.addTo("recipient@example.com")
    email.setSubject("Image HTML Email")
    email.setHtmlMsg("<html><body>Here is an image: <img src=\"cid:image1\"></body></html>")
    email.send()
  }

  def bad_case_6(): Unit = {
    val props = new Properties()
    props.put("mail.smtp.host", "smtp.example.com")
    props.put("mail.smtp.port", "465")
    props.put("mail.smtp.auth", "true")
    // ruleid: scala-insecure-smtp
    props.put("mail.smtp.ssl.enable", "true")
    
    val session = Session.getInstance(props, new Authenticator() {
      override protected def getPasswordAuthentication(): PasswordAuthentication = {
        new PasswordAuthentication("username", "password")
      }
    })
    
    val message = new MimeMessage(session)
    message.setFrom(new InternetAddress("from@example.com"))
    message.setRecipients(Message.RecipientType.TO, "to@example.com")
    message.setSubject("Test Email")
    message.setText("This is a test email")
    Transport.send(message)
  }

  def bad_case_7(): Unit = {
    val email = new SimpleEmail()
    val username = "user@example.com"
    val password = Source.fromFile("credentials.txt").getLines().next()
    
    email.setHostName("smtp.example.com")
    email.setSmtpPort(465)
    email.setAuthentication(username, password)
    // ruleid: scala-insecure-smtp
    email.setSSLOnConnect(true)
    email.setFrom(username)
    email.setSubject("File-based credentials")
    email.setMsg("Email with credentials from file")
    email.addTo("recipient@example.com")
    email.send()
  }

  def bad_case_8(): Unit = {
    def sendNotification(recipient: String, subject: String, content: String): Unit = {
      val email = new SimpleEmail()
      email.setHostName("smtp.company.com")
      email.setSmtpPort(465)
      email.setAuthentication("notifier", "notifier123")
      // ruleid: scala-insecure-smtp
      email.setSSLOnConnect(true)
      email.setFrom("notifications@company.com")
      email.setSubject(subject)
      email.setMsg(content)
      email.addTo(recipient)
      email.send()
    }
    
    sendNotification("user@example.com", "System Alert", "The system has detected an issue")
  }

  def bad_case_9(): Unit = {
    val email = new SimpleEmail()
    
    // Load properties from file
    val props = new Properties()
    props.load(new FileInputStream("mail.properties"))
    
    email.setHostName(props.getProperty("mail.host"))
    email.setSmtpPort(props.getProperty("mail.port").toInt)
    email.setAuthentication(props.getProperty("mail.user"), props.getProperty("mail.password"))
    // ruleid: scala-insecure-smtp
    email.setSSLOnConnect(true)
    email.setFrom(props.getProperty("mail.from"))
    email.setSubject("Properties File Test")
    email.setMsg("Email configured from properties file")
    email.addTo(props.getProperty("mail.recipient"))
    email.send()
  }

  def bad_case_10(): Unit = {
    try {
      val email = new SimpleEmail()
      email.setHostName("smtp.example.com")
      email.setSmtpPort(465)
      
      // Setting SSL first, but not setting check server identity
      // ruleid: scala-insecure-smtp
      email.setSSLOnConnect(true)
      
      email.setAuthentication("username", "password")
      email.setFrom("user@example.com")
      email.setSubject("Test Email with SSL")
      email.setMsg("This is a test email with SSL enabled")
      email.addTo("recipient@example.com")
      email.send()
    } catch {
      case e: Exception => println(s"Failed to send email: ${e.getMessage}")
    }
  }

  def bad_case_11(): Unit = {
    val email = new SimpleEmail()
    
    // Configure email with SSL but explicitly set check server identity to false
    email.setHostName("smtp.example.com")
    email.setSmtpPort(465)
    email.setSSLCheckServerIdentity(false)
    // ruleid: scala-insecure-smtp
    email.setSSLOnConnect(true)
    email.setAuthentication("username", "password")
    email.setFrom("user@example.com")
    email.setSubject("Explicitly Insecure Email")
    email.setMsg("This email explicitly disables server identity checks")
    email.addTo("recipient@example.com")
    email.send()
  }

  def bad_case_12(): Unit = {
    // Using a factory method to create email
    def createEmail(): Email = {
      val email = new SimpleEmail()
      email.setHostName("smtp.example.com")
      email.setSmtpPort(465)
      email.setAuthentication("username", "password")
      // ruleid: scala-insecure-smtp
      email.setSSLOnConnect(true)
      email.setFrom("user@example.com")
      email
    }
    
    val email = createEmail()
    email.setSubject("Factory Method Email")
    email.setMsg("This email was created using a factory method")
    email.addTo("recipient@example.com")
    email.send()
  }

  def bad_case_13(): Unit = {
    // Using conditional logic but still insecure
    val useSSL = true
    val email = new SimpleEmail()
    email.setHostName("smtp.example.com")
    email.setSmtpPort(if (useSSL) 465 else 25)
    email.setAuthentication("username", "password")
    
    if (useSSL) {
      // ruleid: scala-insecure-smtp
      email.setSSLOnConnect(true)
    }
    
    email.setFrom("user@example.com")
    email.setSubject("Conditional SSL Email")
    email.setMsg("This email uses conditional logic for SSL")
    email.addTo("recipient@example.com")
    email.send()
  }

  def bad_case_14(): Unit = {
    // Using a builder pattern but still insecure
    class EmailBuilder {
      private val email = new SimpleEmail()
      
      def withServer(host: String, port: Int): EmailBuilder = {
        email.setHostName(host)
        email.setSmtpPort(port)
        this
      }
      
      def withAuth(username: String, password: String): EmailBuilder = {
        email.setAuthentication(username, password)
        this
      }
      
      def withSSL(): EmailBuilder = {
        // ruleid: scala-insecure-smtp
        email.setSSLOnConnect(true)
        this
      }
      
      def withSender(address: String): EmailBuilder = {
        email.setFrom(address)
        this
      }
      
      def build(): Email = email
    }
    
    val email = new EmailBuilder()
      .withServer("smtp.example.com", 465)
      .withAuth("username", "password")
      .withSSL()
      .withSender("user@example.com")
      .build()
      
    email.setSubject("Builder Pattern Email")
    email.setMsg("This email was built using the builder pattern")
    email.addTo("recipient@example.com")
    email.send()
  }

  def bad_case_15(): Unit = {
    // Using Try for error handling but still insecure
    val result = Try {
      val email = new SimpleEmail()
      email.setHostName("smtp.example.com")
      email.setSmtpPort(465)
      email.setAuthentication("username", "password")
      // ruleid: scala-insecure-smtp
      email.setSSLOnConnect(true)
      email.setFrom("user@example.com")
      email.setSubject("Try-wrapped Email")
      email.setMsg("This email uses Try for error handling")
      email.addTo("recipient@example.com")
      email.send()
      "Email sent successfully"
    }
    
    result match {
      case Success(message) => println(message)
      case Failure(exception) => println(s"Failed to send email: ${exception.getMessage}")
    }
  }

  // True Negative Examples (Secure Code)

  def good_case_1(): Unit = {
    val email = new SimpleEmail()
    email.setHostName("smtp.example.com")
    email.setSmtpPort(465)
    email.setAuthentication("username", "password")
    // ok: scala-insecure-smtp
    email.setSSLCheckServerIdentity(true)
    email.setSSLOnConnect(true)
    email.setFrom("user@example.com")
    email.setSubject("Test Subject")
    email.setMsg("Test Message")
    email.addTo("recipient@example.com")
    email.send()
  }

  def good_case_2(): Unit = {
    val email = new HtmlEmail()
    email.setHostName("smtp.example.com")
    email.setSmtpPort(587)
    // ok: scala-insecure-smtp
    email.setSSLCheckServerIdentity(true)
    email.setSSLOnConnect(true)
    email.setAuthentication("username", "password123")
    email.setFrom("sender@example.com")
    email.setSubject("HTML Email Test")
    email.setHtmlMsg("<html><body><h1>Test HTML Message</h1></body></html>")
    email.addTo("recipient@example.com")
    email.send()
  }

  def good_case_3(): Unit = {
    try {
      val email = new MultiPartEmail()
      email.setHostName("smtp.gmail.com")
      // ok: scala-insecure-smtp
      email.setSSLCheckServerIdentity(true)
      email.setSSLOnConnect(true)
      email.setSmtpPort(465)
      email.setAuthentication("user@gmail.com", "gmailPassword")
      email.setFrom("user@gmail.com", "Sender Name")
      email.addTo("recipient@example.com")
      email.setSubject("Multipart Email Test")
      email.setMsg("This is a test multipart email")
      email.send()
    } catch {
      case e: EmailException => println(s"Error sending email: ${e.getMessage}")
    }
  }

  def good_case_4(): Unit = {
    val config = ConfigFactory.load()
    val email = new SimpleEmail()
    email.setHostName(config.getString("smtp.host"))
    email.setSmtpPort(config.getInt("smtp.port"))
    email.setAuthentication(config.getString("smtp.username"), config.getString("smtp.password"))
    // ok: scala-insecure-smtp
    email.setSSLCheckServerIdentity(true)
    email.setSSLOnConnect(true)
    email.setFrom(config.getString("smtp.from"))
    email.setSubject("Configuration-based Email")
    email.setMsg("Email with configuration")
    email.addTo(config.getString("smtp.recipient"))
    email.send()
  }

  def good_case_5(): Unit = {
    val email = new ImageHtmlEmail()
    // Setting up the mail server
    email.setHostName("mail.server.com")
    email.setSmtpPort(587)
    email.setAuthentication("username", "password")
    // ok: scala-insecure-smtp
    email.setSSLCheckServerIdentity(true)
    email.setSSLOnConnect(true)
    email.setFrom("user@example.com")
    email.addTo("recipient@example.com")
    email.setSubject("Image HTML Email")
    email.setHtmlMsg("<html><body>Here is an image: <img src=\"cid:image1\"></body></html>")
    email.send()
  }

  def good_case_6(): Unit = {
    val props = new Properties()
    props.put("mail.smtp.host", "smtp.example.com")
    props.put("mail.smtp.port", "465")
    props.put("mail.smtp.auth", "true")
    // ok: scala-insecure-smtp
    props.put("mail.smtp.ssl.checkserveridentity", "true")
    props.put("mail.smtp.ssl.enable", "true")
    
    val session = Session.getInstance(props, new Authenticator() {
      override protected def getPasswordAuthentication(): PasswordAuthentication = {
        new PasswordAuthentication("username", "password")
      }
    })
    
    val message = new MimeMessage(session)
    message.setFrom(new InternetAddress("from@example.com"))
    message.setRecipients(Message.RecipientType.TO, "to@example.com")
    message.setSubject("Test Email")
    message.setText("This is a test email")
    Transport.send(message)
  }

  def good_case_7(): Unit = {
    val email = new SimpleEmail()
    val username = "user@example.com"
    val password = Source.fromFile("credentials.txt").getLines().next()
    
    email.setHostName("smtp.example.com")
    email.setSmtpPort(465)
    email.setAuthentication(username, password)
    // ok: scala-insecure-smtp
    email.setSSLCheckServerIdentity(true)
    email.setSSLOnConnect(true)
    email.setFrom(username)
    email.setSubject("File-based credentials")
    email.setMsg("Email with credentials from file")
    email.addTo("recipient@example.com")
    email.send()
  }

  def good_case_8(): Unit = {
    def sendNotification(recipient: String, subject: String, content: String): Unit = {
      val email = new SimpleEmail()
      email.setHostName("smtp.company.com")
      email.setSmtpPort(465)
      email.setAuthentication("notifier", "notifier123")
      // ok: scala-insecure-smtp
      email.setSSLCheckServerIdentity(true)
      email.setSSLOnConnect(true)
      email.setFrom("notifications@company.com")
      email.setSubject(subject)
      email.setMsg(content)
      email.addTo(recipient)
      email.send()
    }
    
    sendNotification("user@example.com", "System Alert", "The system has detected an issue")
  }

  def good_case_9(): Unit = {
    val email = new SimpleEmail()
    
    // Load properties from file
    val props = new Properties()
    props.load(new FileInputStream("mail.properties"))
    
    email.setHostName(props.getProperty("mail.host"))
    email.setSmtpPort(props.getProperty("mail.port").toInt)
    email.setAuthentication(props.getProperty("mail.user"), props.getProperty("mail.password"))
    // ok: scala-insecure-smtp
    email.setSSLCheckServerIdentity(true)
    email.setSSLOnConnect(true)
    email.setFrom(props.getProperty("mail.from"))
    email.setSubject("Properties File Test")
    email.setMsg("Email configured from properties file")
    email.addTo(props.getProperty("mail.recipient"))
    email.send()
  }

  def good_case_10(): Unit = {
    // Using a non-SSL connection (no SSL, no need for server identity check)
    val email = new SimpleEmail()
    email.setHostName("smtp.example.com")
    email.setSmtpPort(25)
    email.setAuthentication("username", "password")
    // ok: scala-insecure-smtp
    // Not using SSL at all, so no vulnerability
    email.setFrom("user@example.com")
    email.setSubject("Non-SSL Email")
    email.setMsg("This email doesn't use SSL")
    email.addTo("recipient@example.com")
    email.send()
  }

  def good_case_11(): Unit = {
    // Using TLS instead of SSL
    val email = new SimpleEmail()
    email.setHostName("smtp.example.com")
    email.setSmtpPort(587)
    email.setAuthentication("username", "password")
    // ok: scala-insecure-smtp
    email.setStartTLSEnabled(true)
    email.setStartTLSRequired(true)
    email.setFrom("user@example.com")
    email.setSubject("TLS Email")
    email.setMsg("This email uses TLS instead of SSL")
    email.addTo("recipient@example.com")
    email.send()
  }

  def good_case_12(): Unit = {
    // Using a factory method to create secure email
    def createSecureEmail(): Email = {
      val email = new SimpleEmail()
      email.setHostName("smtp.example.com")
      email.setSmtpPort(465)
      email.setAuthentication("username", "password")
      // ok: scala-insecure-smtp
      email.setSSLCheckServerIdentity(true)
      email.setSSLOnConnect(true)
      email.setFrom("user@example.com")
      email
    }
    
    val email = createSecureEmail()
    email.setSubject("Secure Factory Method Email")
    email.setMsg("This email was created using a secure factory method")
    email.addTo("recipient@example.com")
    email.send()
  }

  def good_case_13(): Unit = {
    // Using conditional logic with secure configuration
    val useSSL = true
    val email = new SimpleEmail()
    email.setHostName("smtp.example.com")
    email.setSmtpPort(if (useSSL) 465 else 25)
    email.setAuthentication("username", "password")
    
    if (useSSL) {
      // ok: scala-insecure-smtp
      email.setSSLCheckServerIdentity(true)
      email.setSSLOnConnect(true)
    }
    
    email.setFrom("user@example.com")
    email.setSubject("Conditional Secure SSL Email")
    email.setMsg("This email uses conditional logic for secure SSL")
    email.addTo("recipient@example.com")
    email.send()
  }

  def good_case_14(): Unit = {
    // Using a builder pattern with secure configuration
    class SecureEmailBuilder {
      private val email = new SimpleEmail()
      
      def withServer(host: String, port: Int): SecureEmailBuilder = {
        email.setHostName(host)
        email.setSmtpPort(port)
        this
      }
      
      def withAuth(username: String, password: String): SecureEmailBuilder = {
        email.setAuthentication(username, password)
        this
      }
      
      def withSecureSSL(): SecureEmailBuilder = {
        // ok: scala-insecure-smtp
        email.setSSLCheckServerIdentity(true)
        email.setSSLOnConnect(true)
        this
      }
      
      def withSender(address: String): SecureEmailBuilder = {
        email.setFrom(address)
        this
      }
      
      def build(): Email = email
    }
    
    val email = new SecureEmailBuilder()
      .withServer("smtp.example.com", 465)
      .withAuth("username", "password")
      .withSecureSSL()
      .withSender("user@example.com")
      .build()
      
    email.setSubject("Secure Builder Pattern Email")
    email.setMsg("This email was built using the secure builder pattern")
    email.addTo("recipient@example.com")
    email.send()
  }

  def good_case_15(): Unit = {
    // Using Try for error handling with secure configuration
    val result = Try {
      val email = new SimpleEmail()
      email.setHostName("smtp.example.com")
      email.setSmtpPort(465)
      email.setAuthentication("username", "password")
      // ok: scala-insecure-smtp
      email.setSSLCheckServerIdentity(true)
      email.setSSLOnConnect(true)
      email.setFrom("user@example.com")
      email.setSubject("Secure Try-wrapped Email")
      email.setMsg("This email uses Try for error handling with secure configuration")
      email.addTo("recipient@example.com")
      email.send()
      "Email sent successfully"
    }
    
    result match {
      case Success(message) => println(message)
      case Failure(exception) => println(s"Failed to send email: ${exception.getMessage}")
    }
  }
}