import java.util.Random
import scala.util.Random as ScalaRandom
import java.security.SecureRandom
import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Success, Failure}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

// True Positives (Insecure random number generation)

def bad_case_1(): Unit = {
  // Using java.util.Random for generating a token
  // ruleid: scala-insecure-random
  val random = new Random()
  val token = new Array[Byte](16)
  random.nextBytes(token)
  println(s"Generated token: ${token.map("%02x".format(_)).mkString}")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_2(): Unit = {
  // Using Math.random() for generating a session ID
  // ruleid: scala-insecure-random
  val sessionId = Math.random().toString.substring(2, 10)
  println(s"Session ID: $sessionId")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_3(): Unit = {
  // Using scala.util.Random for generating a password
  // ruleid: scala-insecure-random
  val random = ScalaRandom
  val password = random.alphanumeric.take(12).mkString
  println(s"Generated password: $password")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_4(): Unit = {
  // Using java.util.Random for generating an encryption key
  // ruleid: scala-insecure-random
  val random = new Random(System.currentTimeMillis())
  val key = new Array[Byte](32)
  random.nextBytes(key)
  println(s"Encryption key: ${key.map("%02x".format(_)).mkString}")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_5(): Unit = {
  // Using scala.util.Random for generating a nonce
  // ruleid: scala-insecure-random
  val nonce = ScalaRandom.nextLong()
  println(s"Nonce: $nonce")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_6(): Unit = {
  // Using java.util.Random in a class constructor
  class TokenGenerator {
    // ruleid: scala-insecure-random
    private val random = new Random()
    
    def generateToken(length: Int): String = {
      val bytes = new Array[Byte](length)
      random.nextBytes(bytes)
      bytes.map("%02x".format(_)).mkString
    }
  }
  
  val generator = new TokenGenerator()
  println(s"Token: ${generator.generateToken(16)}")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_7(): Unit = {
  // Using scala.util.Random for generating a salt
  // ruleid: scala-insecure-random
  val salt = ScalaRandom.nextString(16)
  println(s"Salt: $salt")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_8(): Unit = {
  // Using java.util.Random with seed for generating a verification code
  // ruleid: scala-insecure-random
  val random = new Random(42) // Fixed seed makes it even more predictable
  val verificationCode = random.nextInt(900000) + 100000 // 6-digit code
  println(s"Verification code: $verificationCode")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_9(): Unit = {
  // Using scala.util.Random in a trait
  trait RandomGenerator {
    // ruleid: scala-insecure-random
    val random = ScalaRandom
    
    def nextBytes(length: Int): Array[Byte] = {
      val bytes = new Array[Byte](length)
      random.nextBytes(bytes)
      bytes
    }
  }
  
  class SecurityTokenGenerator extends RandomGenerator {
    def generateToken(): String = {
      nextBytes(16).map("%02x".format(_)).mkString
    }
  }
  
  val generator = new SecurityTokenGenerator()
  println(s"Security token: ${generator.generateToken()}")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_10(): Unit = {
  // Using Math.random() for generating a UUID-like string
  // ruleid: scala-insecure-random
  val uuid = f"${Math.random()}%f-${Math.random()}%f-${Math.random()}%f-${Math.random()}%f"
  println(s"UUID-like: $uuid")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_11(): Unit = {
  // Using java.util.Random in an asynchronous context
  // ruleid: scala-insecure-random
  val random = new Random()
  
  val futureToken = Future {
    val token = new Array[Byte](32)
    random.nextBytes(token)
    token.map("%02x".format(_)).mkString
  }
  
  futureToken.onComplete {
    case Success(token) => println(s"Async token: $token")
    case Failure(e) => println(s"Error: ${e.getMessage}")
  }
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_12(): Unit = {
  // Using scala.util.Random with a custom alphabet for generating a random string
  // ruleid: scala-insecure-random
  val random = ScalaRandom
  val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  val randomString = (1 to 20).map(_ => alphabet(random.nextInt(alphabet.length))).mkString
  println(s"Random string: $randomString")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_13(): Unit = {
  // Using java.util.Random for shuffling a list (e.g., for a security question selection)
  // ruleid: scala-insecure-random
  val random = new Random()
  val securityQuestions = List(
    "What was your first pet's name?",
    "What is your mother's maiden name?",
    "In what city were you born?",
    "What was the name of your first school?"
  )
  
  val shuffled = random.shuffle(securityQuestions)
  println(s"Selected security question: ${shuffled.head}")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_14(): Object = {
  // Using scala.util.Random in an object
  object TokenGenerator {
    // ruleid: scala-insecure-random
    private val random = ScalaRandom
    
    def generateToken(length: Int): String = {
      val bytes = new Array[Byte](length)
      random.nextBytes(bytes)
      bytes.map("%02x".format(_)).mkString
    }
  }
  
  println(s"Object token: ${TokenGenerator.generateToken(16)}")
  TokenGenerator
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

def bad_case_15(): Unit = {
  // Using java.util.Random with a lambda function
  // ruleid: scala-insecure-random
  val randomGenerator = () => {
    val random = new Random()
    val bytes = new Array[Byte](16)
    random.nextBytes(bytes)
    bytes.map("%02x".format(_)).mkString
  }
  
  println(s"Lambda token: ${randomGenerator()}")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

// True Negatives (Secure random number generation)

def good_case_1(): Unit = {
  // Using java.security.SecureRandom for generating a token
  // ok: scala-insecure-random
  val secureRandom = new SecureRandom()
  val token = new Array[Byte](16)
  secureRandom.nextBytes(token)
  println(s"Generated secure token: ${token.map("%02x".format(_)).mkString}")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_2(): Unit = {
  // Using java.security.SecureRandom for generating a session ID
  // ok: scala-insecure-random
  val secureRandom = new SecureRandom()
  val sessionId = new Array[Byte](8)
  secureRandom.nextBytes(sessionId)
  val sessionIdHex = sessionId.map("%02x".format(_)).mkString
  println(s"Secure session ID: $sessionIdHex")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_3(): Unit = {
  // Using java.security.SecureRandom with getInstance method
  // ok: scala-insecure-random
  val secureRandom = SecureRandom.getInstance("SHA1PRNG")
  val password = new Array[Byte](12)
  secureRandom.nextBytes(password)
  val securePassword = password.map(b => (b & 0xff) % 94 + 33).map(_.toChar).mkString
  println(s"Secure password: $securePassword")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_4(): Unit = {
  // Using java.security.SecureRandom for generating an encryption key
  // ok: scala-insecure-random
  val secureRandom = new SecureRandom()
  val key = new Array[Byte](32)
  secureRandom.nextBytes(key)
  println(s"Secure encryption key: ${key.map("%02x".format(_)).mkString}")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_5(): Unit = {
  // Using java.security.SecureRandom for generating a nonce
  // ok: scala-insecure-random
  val secureRandom = new SecureRandom()
  val nonce = secureRandom.nextLong()
  println(s"Secure nonce: $nonce")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_6(): Unit = {
  // Using java.security.SecureRandom in a class constructor
  class SecureTokenGenerator {
    // ok: scala-insecure-random
    private val secureRandom = new SecureRandom()
    
    def generateToken(length: Int): String = {
      val bytes = new Array[Byte](length)
      secureRandom.nextBytes(bytes)
      bytes.map("%02x".format(_)).mkString
    }
  }
  
  val generator = new SecureTokenGenerator()
  println(s"Secure token: ${generator.generateToken(16)}")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_7(): Unit = {
  // Using java.security.SecureRandom for generating a salt
  // ok: scala-insecure-random
  val secureRandom = new SecureRandom()
  val salt = new Array[Byte](16)
  secureRandom.nextBytes(salt)
  val saltHex = salt.map("%02x".format(_)).mkString
  println(s"Secure salt: $saltHex")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_8(): Unit = {
  // Using java.security.SecureRandom for generating a verification code
  // ok: scala-insecure-random
  val secureRandom = new SecureRandom()
  val verificationCode = secureRandom.nextInt(900000) + 100000 // 6-digit code
  println(s"Secure verification code: $verificationCode")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_9(): Unit = {
  // Using java.security.SecureRandom in a trait
  trait SecureRandomGenerator {
    // ok: scala-insecure-random
    val secureRandom = new SecureRandom()
    
    def nextBytes(length: Int): Array[Byte] = {
      val bytes = new Array[Byte](length)
      secureRandom.nextBytes(bytes)
      bytes
    }
  }
  
  class SecureTokenGenerator extends SecureRandomGenerator {
    def generateToken(): String = {
      nextBytes(16).map("%02x".format(_)).mkString
    }
  }
  
  val generator = new SecureTokenGenerator()
  println(s"Secure token from trait: ${generator.generateToken()}")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_10(): Unit = {
  // Using java.security.SecureRandom for generating UUID-like strings
  // ok: scala-insecure-random
  val secureRandom = new SecureRandom()
  val bytes = new Array[Byte](16)
  secureRandom.nextBytes(bytes)
  
  // Format similar to UUID
  val uuid = s"${bytes.slice(0, 4).map("%02x".format(_)).mkString}-" +
             s"${bytes.slice(4, 6).map("%02x".format(_)).mkString}-" +
             s"${bytes.slice(6, 8).map("%02x".format(_)).mkString}-" +
             s"${bytes.slice(8, 10).map("%02x".format(_)).mkString}-" +
             s"${bytes.slice(10, 16).map("%02x".format(_)).mkString}"
             
  println(s"Secure UUID-like: $uuid")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_11(): Unit = {
  // Using java.security.SecureRandom in an asynchronous context
  // ok: scala-insecure-random
  val secureRandom = new SecureRandom()
  
  val futureToken = Future {
    val token = new Array[Byte](32)
    secureRandom.nextBytes(token)
    token.map("%02x".format(_)).mkString
  }
  
  futureToken.onComplete {
    case Success(token) => println(s"Secure async token: $token")
    case Failure(e) => println(s"Error: ${e.getMessage}")
  }
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_12(): Unit = {
  // Using java.security.SecureRandom with a custom alphabet for generating a random string
  // ok: scala-insecure-random
  val secureRandom = new SecureRandom()
  val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  val randomString = (1 to 20).map(_ => alphabet(secureRandom.nextInt(alphabet.length))).mkString
  println(s"Secure random string: $randomString")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_13(): Unit = {
  // Using java.security.SecureRandom for shuffling a list (e.g., for a security question selection)
  // ok: scala-insecure-random
  val secureRandom = new SecureRandom()
  val securityQuestions = List(
    "What was your first pet's name?",
    "What is your mother's maiden name?",
    "In what city were you born?",
    "What was the name of your first school?"
  )
  
  // Create a secure shuffle implementation
  def secureShuffleList[T](list: List[T], random: SecureRandom): List[T] = {
    val array = list.toArray
    for (i <- array.length - 1 to 1 by -1) {
      val j = random.nextInt(i + 1)
      val temp = array(i)
      array(i) = array(j)
      array(j) = temp
    }
    array.toList
  }
  
  val shuffled = secureShuffleList(securityQuestions, secureRandom)
  println(s"Securely selected security question: ${shuffled.head}")
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_14(): Object = {
  // Using java.security.SecureRandom in an object
  object SecureTokenGenerator {
    // ok: scala-insecure-random
    private val secureRandom = new SecureRandom()
    
    def generateToken(length: Int): String = {
      val bytes = new Array[Byte](length)
      secureRandom.nextBytes(bytes)
      bytes.map("%02x".format(_)).mkString
    }
  }
  
  println(s"Secure object token: ${SecureTokenGenerator.generateToken(16)}")
  SecureTokenGenerator
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

def good_case_15(): Unit = {
  // Using java.security.SecureRandom with a lambda function
  // ok: scala-insecure-random
  val secureRandomGenerator = () => {
    val secureRandom = new SecureRandom()
    val bytes = new Array[Byte](16)
    secureRandom.nextBytes(bytes)
    bytes.map("%02x".format(_)).mkString
  }
  
  println(s"Secure lambda token: ${secureRandomGenerator()}")
}
// {/fact}