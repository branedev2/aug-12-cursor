// Integer Overflow Examples in Scala
// Rule ID: scala-integer-overflow

object IntegerOverflowExamples {
  
  // True Positive Examples (Vulnerable Code)
  
  def bad_case_1(): Unit = {
    val a: Int = Int.MaxValue
    val b: Int = 1
    // ruleid: scala-integer-overflow
    val result = a + b // This will overflow
    println(s"Result: $result") // Will print a negative number due to overflow
  }
  
  def bad_case_2(): Unit = {
    val a: Int = 2000000000
    val b: Int = 1000000000
    // ruleid: scala-integer-overflow
    val result = a + b // This will overflow
    println(s"Result: $result")
  }
  
  def bad_case_3(): Unit = {
    val a: Byte = 127 // Max value for Byte
    val b: Byte = 1
    // ruleid: scala-integer-overflow
    val result: Byte = (a + b).toByte // This will overflow
    println(s"Result: $result") // Will print -128
  }
  
  def bad_case_4(): Unit = {
    val a: Short = Short.MaxValue
    val b: Short = 1
    // ruleid: scala-integer-overflow
    val result: Short = (a + b).toShort // This will overflow
    println(s"Result: $result")
  }
  
  def bad_case_5(): Unit = {
    val a: Int = 100000
    val b: Int = 100000
    // ruleid: scala-integer-overflow
    val result = a * b // This might overflow if the result exceeds Int.MaxValue
    println(s"Result: $result")
  }
  
  def bad_case_6(): Unit = {
    val a: Long = Long.MaxValue
    val b: Long = 1
    // ruleid: scala-integer-overflow
    val result = a + b // This will overflow
    println(s"Result: $result")
  }
  
  def bad_case_7(): Unit = {
    val iterations: Int = Int.MaxValue
    var counter: Int = 0
    
    for (i <- 1 to 1000) {
      // ruleid: scala-integer-overflow
      counter += iterations // This will eventually overflow
    }
    println(s"Counter: $counter")
  }
  
  def bad_case_8(): Unit = {
    val a: Int = -2147483648 // Int.MinValue
    // ruleid: scala-integer-overflow
    val result = -a // This will overflow because -Int.MinValue > Int.MaxValue
    println(s"Result: $result")
  }
  
  def bad_case_9(): Unit = {
    val a: Int = 1000000000
    // ruleid: scala-integer-overflow
    val result = a * a * a // This will overflow
    println(s"Result: $result")
  }
  
  def bad_case_10(): Unit = {
    val userInput = "2147483647" // Max Int value
    val a: Int = userInput.toInt
    // ruleid: scala-integer-overflow
    val result = a + 1 // This will overflow
    println(s"Result: $result")
  }
  
  def bad_case_11(): Unit = {
    val a: Int = Int.MaxValue
    val b: Int = Int.MaxValue
    // ruleid: scala-integer-overflow
    val result = a * b // This will overflow significantly
    println(s"Result: $result")
  }
  
  def bad_case_12(): Unit = {
    val factorial: Int = calculateFactorial(20) // 20! is much larger than Int.MaxValue
    println(s"Factorial: $factorial") // Will print an incorrect value due to overflow
  }
  
  def calculateFactorial(n: Int): Int = {
    var result: Int = 1
    for (i <- 2 to n) {
      // ruleid: scala-integer-overflow
      result *= i // Will overflow for large values of n
    }
    result
  }
  
  def bad_case_13(): Unit = {
    val a: Int = 100000
    val b: Int = 100000
    val c: Int = 100
    // ruleid: scala-integer-overflow
    val result = a * b * c // This will overflow
    println(s"Result: $result")
  }
  
  def bad_case_14(): Unit = {
    val values = List(Int.MaxValue, 1, 2, 3)
    // ruleid: scala-integer-overflow
    val sum = values.sum // This will overflow
    println(s"Sum: $sum")
  }
  
  def bad_case_15(): Unit = {
    val base: Int = 2
    // ruleid: scala-integer-overflow
    val result = Math.pow(base, 31).toInt // 2^31 exceeds Int.MaxValue
    println(s"Result: $result")
  }
  
  // True Negative Examples (Safe Code)
  
  def good_case_1(): Unit = {
    val a: Int = Int.MaxValue
    val b: Int = 1
    // ok: scala-integer-overflow
    val result: Long = a.toLong + b // Converting to Long prevents overflow
    println(s"Result: $result")
  }
  
  def good_case_2(): Unit = {
    val a: Int = 2000000000
    val b: Int = 1000000000
    // Check for potential overflow before performing the operation
    // ok: scala-integer-overflow
    if (a > Int.MaxValue - b) {
      println("Operation would cause overflow")
    } else {
      val result = a + b
      println(s"Result: $result")
    }
  }
  
  def good_case_3(): Unit = {
    val a: Byte = 127 // Max value for Byte
    val b: Byte = 1
    // ok: scala-integer-overflow
    val result: Short = (a.toShort + b.toShort).toShort // Using a wider type prevents overflow
    println(s"Result: $result")
  }
  
  def good_case_4(): Unit = {
    val a: Short = Short.MaxValue
    val b: Short = 1
    // ok: scala-integer-overflow
    val result: Int = a.toInt + b.toInt // Using a wider type prevents overflow
    println(s"Result: $result")
  }
  
  def good_case_5(): Unit = {
    val a: Int = 100000
    val b: Int = 100000
    // ok: scala-integer-overflow
    val result: Long = a.toLong * b.toLong // Using Long prevents overflow
    println(s"Result: $result")
  }
  
  def good_case_6(): Unit = {
    val a: Long = Long.MaxValue
    val b: Long = 1
    // ok: scala-integer-overflow
    val result = BigInt(a) + BigInt(b) // Using BigInt prevents overflow
    println(s"Result: $result")
  }
  
  def good_case_7(): Unit = {
    val iterations: Int = Int.MaxValue
    var counter: BigInt = BigInt(0)
    
    for (i <- 1 to 1000) {
      // ok: scala-integer-overflow
      counter += iterations // Using BigInt prevents overflow
    }
    println(s"Counter: $counter")
  }
  
  def good_case_8(): Unit = {
    val a: Int = Int.MinValue
    // ok: scala-integer-overflow
    val result: Long = -(a.toLong) // Converting to Long before negation prevents overflow
    println(s"Result: $result")
  }
  
  def good_case_9(): Unit = {
    val a: Int = 1000000000
    // ok: scala-integer-overflow
    val result: BigInt = BigInt(a) * BigInt(a) * BigInt(a) // Using BigInt prevents overflow
    println(s"Result: $result")
  }
  
  def good_case_10(): Unit = {
    val userInput = "2147483647" // Max Int value
    try {
      val a: Int = userInput.toInt
      // ok: scala-integer-overflow
      if (a == Int.MaxValue) {
        println("Cannot increment further, would cause overflow")
      } else {
        val result = a + 1
        println(s"Result: $result")
      }
    } catch {
      case e: NumberFormatException => println("Invalid input")
    }
  }
  
  def good_case_11(): Unit = {
    val a: Int = Int.MaxValue
    val b: Int = Int.MaxValue
    // ok: scala-integer-overflow
    val result: BigInt = BigInt(a) * BigInt(b) // Using BigInt prevents overflow
    println(s"Result: $result")
  }
  
  def good_case_12(): Unit = {
    val factorial: BigInt = calculateFactorialSafely(20) // 20! is much larger than Int.MaxValue
    println(s"Factorial: $factorial") // Will print the correct value
  }
  
  def calculateFactorialSafely(n: Int): BigInt = {
    var result: BigInt = BigInt(1)
    for (i <- 2 to n) {
      // ok: scala-integer-overflow
      result *= i // Using BigInt prevents overflow
    }
    result
  }
  
  def good_case_13(): Unit = {
    val a: Int = 100000
    val b: Int = 100000
    val c: Int = 100
    // ok: scala-integer-overflow
    val result: BigInt = BigInt(a) * BigInt(b) * BigInt(c) // Using BigInt prevents overflow
    println(s"Result: $result")
  }
  
  def good_case_14(): Unit = {
    val values = List(Int.MaxValue, 1, 2, 3)
    // ok: scala-integer-overflow
    val sum = values.foldLeft(BigInt(0))((acc, value) => acc + value) // Using BigInt prevents overflow
    println(s"Sum: $sum")
  }
  
  def good_case_15(): Unit = {
    val base: Int = 2
    // ok: scala-integer-overflow
    val result = BigInt(base).pow(31) // Using BigInt prevents overflow
    println(s"Result: $result")
  }
}