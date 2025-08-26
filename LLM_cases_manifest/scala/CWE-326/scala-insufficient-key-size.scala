// File: InsufficientKeySizeExamples.scala

import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.security.spec.DSAParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.SecretKeyFactory
import java.security.AlgorithmParameters
import java.security.spec.ECGenParameterSpec
import javax.crypto.spec.DHParameterSpec
import java.math.BigInteger

object InsufficientKeySizeExamples {

  // True Positive Examples (Vulnerable Code)

  def bad_case_1(): Unit = {
    // RSA with insufficient key size (1024 bits)
    val keyGen = KeyPairGenerator.getInstance("RSA")
    // ruleid: scala-insufficient-key-size
    keyGen.initialize(1024)
    val keyPair = keyGen.generateKeyPair()
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic)
  }

  def bad_case_2(): Unit = {
    // DSA with insufficient key size (1024 bits)
    val keyGen = KeyPairGenerator.getInstance("DSA")
    // ruleid: scala-insufficient-key-size
    keyGen.initialize(1024, new SecureRandom())
    val keyPair = keyGen.generateKeyPair()
  }

  def bad_case_3(): Unit = {
    // AES with insufficient key size (64 bits)
    val keyGen = KeyGenerator.getInstance("AES")
    // ruleid: scala-insufficient-key-size
    keyGen.init(64)
    val secretKey = keyGen.generateKey()
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
  }

  def bad_case_4(): Unit = {
    // DES (inherently insecure with 56-bit key)
    val keyGen = KeyGenerator.getInstance("DES")
    // ruleid: scala-insufficient-key-size
    keyGen.init(56)
    val secretKey = keyGen.generateKey()
    val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
  }

  def bad_case_5(): Unit = {
    // Blowfish with insufficient key size (64 bits)
    val keyGen = KeyGenerator.getInstance("Blowfish")
    // ruleid: scala-insufficient-key-size
    keyGen.init(64)
    val secretKey = keyGen.generateKey()
    val cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
  }

  def bad_case_6(): Unit = {
    // RSA with insufficient key size using RSAKeyGenParameterSpec
    val keyGen = KeyPairGenerator.getInstance("RSA")
    val publicExponent = RSAKeyGenParameterSpec.F4
    // ruleid: scala-insufficient-key-size
    keyGen.initialize(new RSAKeyGenParameterSpec(1024, publicExponent))
    val keyPair = keyGen.generateKeyPair()
  }

  def bad_case_7(): Unit = {
    // Creating AES key with insufficient size from raw bytes
    val keyBytes = new Array[Byte](8) // 64 bits
    new SecureRandom().nextBytes(keyBytes)
    // ruleid: scala-insufficient-key-size
    val secretKey = new SecretKeySpec(keyBytes, "AES")
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
  }

  def bad_case_8(): Unit = {
    // RC4 with insufficient key size
    val keyGen = KeyGenerator.getInstance("RC4")
    // ruleid: scala-insufficient-key-size
    keyGen.init(40)
    val secretKey = keyGen.generateKey()
    val cipher = Cipher.getInstance("RC4")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
  }

  def bad_case_9(): Unit = {
    // HMAC with insufficient key size
    val keyGen = KeyGenerator.getInstance("HmacSHA256")
    // ruleid: scala-insufficient-key-size
    keyGen.init(64)
    val secretKey = keyGen.generateKey()
  }

  def bad_case_10(): Unit = {
    // PBE with insufficient key size
    val salt = new Array[Byte](8)
    new SecureRandom().nextBytes(salt)
    val iterationCount = 1000
    // ruleid: scala-insufficient-key-size
    val keySpec = new PBEKeySpec("password".toCharArray(), salt, iterationCount, 64)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val secretKey = factory.generateSecret(keySpec)
  }

  def bad_case_11(): Unit = {
    // 3DES with insufficient effective key size
    val keyGen = KeyGenerator.getInstance("DESede")
    // ruleid: scala-insufficient-key-size
    keyGen.init(112) // 3DES with 112 bits (effectively 80 bits of security)
    val secretKey = keyGen.generateKey()
    val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
  }

  def bad_case_12(): Unit = {
    // ElGamal with insufficient key size
    val keyGen = KeyPairGenerator.getInstance("ElGamal")
    // ruleid: scala-insufficient-key-size
    keyGen.initialize(512)
    val keyPair = keyGen.generateKeyPair()
  }

  def bad_case_13(): Unit = {
    // DH with insufficient key size
    val keyGen = KeyPairGenerator.getInstance("DH")
    // ruleid: scala-insufficient-key-size
    keyGen.initialize(512)
    val keyPair = keyGen.generateKeyPair()
  }

  def bad_case_14(): Unit = {
    // DH with insufficient key size using DHParameterSpec
    val p = BigInteger.probablePrime(512, new SecureRandom())
    val g = BigInteger.valueOf(2)
    // ruleid: scala-insufficient-key-size
    val dhParams = new DHParameterSpec(p, g)
    val keyGen = KeyPairGenerator.getInstance("DH")
    keyGen.initialize(dhParams)
    val keyPair = keyGen.generateKeyPair()
  }

  def bad_case_15(): Unit = {
    // RSA with insufficient key size using direct parameter
    val keyGen = KeyPairGenerator.getInstance("RSA")
    val random = new SecureRandom()
    // ruleid: scala-insufficient-key-size
    keyGen.initialize(512, random)
    val keyPair = keyGen.generateKeyPair()
  }

  // True Negative Examples (Secure Code)

  def good_case_1(): Unit = {
    // RSA with sufficient key size (2048 bits)
    val keyGen = KeyPairGenerator.getInstance("RSA")
    // ok: scala-insufficient-key-size
    keyGen.initialize(2048)
    val keyPair = keyGen.generateKeyPair()
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic)
  }

  def good_case_2(): Unit = {
    // DSA with sufficient key size (2048 bits)
    val keyGen = KeyPairGenerator.getInstance("DSA")
    // ok: scala-insufficient-key-size
    keyGen.initialize(2048, new SecureRandom())
    val keyPair = keyGen.generateKeyPair()
  }

  def good_case_3(): Unit = {
    // AES with sufficient key size (128 bits)
    val keyGen = KeyGenerator.getInstance("AES")
    // ok: scala-insufficient-key-size
    keyGen.init(128)
    val secretKey = keyGen.generateKey()
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
  }

  def good_case_4(): Unit = {
    // AES with strong key size (256 bits)
    val keyGen = KeyGenerator.getInstance("AES")
    // ok: scala-insufficient-key-size
    keyGen.init(256)
    val secretKey = keyGen.generateKey()
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
  }

  def good_case_5(): Unit = {
    // Blowfish with sufficient key size (128 bits)
    val keyGen = KeyGenerator.getInstance("Blowfish")
    // ok: scala-insufficient-key-size
    keyGen.init(128)
    val secretKey = keyGen.generateKey()
    val cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
  }

  def good_case_6(): Unit = {
    // RSA with sufficient key size using RSAKeyGenParameterSpec
    val keyGen = KeyPairGenerator.getInstance("RSA")
    val publicExponent = RSAKeyGenParameterSpec.F4
    // ok: scala-insufficient-key-size
    keyGen.initialize(new RSAKeyGenParameterSpec(2048, publicExponent))
    val keyPair = keyGen.generateKeyPair()
  }

  def good_case_7(): Unit = {
    // Creating AES key with sufficient size from raw bytes
    val keyBytes = new Array[Byte](16) // 128 bits
    new SecureRandom().nextBytes(keyBytes)
    // ok: scala-insufficient-key-size
    val secretKey = new SecretKeySpec(keyBytes, "AES")
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
  }

  def good_case_8(): Unit = {
    // HMAC with sufficient key size
    val keyGen = KeyGenerator.getInstance("HmacSHA256")
    // ok: scala-insufficient-key-size
    keyGen.init(256)
    val secretKey = keyGen.generateKey()
  }

  def good_case_9(): Unit = {
    // PBE with sufficient key size
    val salt = new Array[Byte](16)
    new SecureRandom().nextBytes(salt)
    val iterationCount = 10000
    // ok: scala-insufficient-key-size
    val keySpec = new PBEKeySpec("password".toCharArray(), salt, iterationCount, 256)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val secretKey = factory.generateSecret(keySpec)
  }

  def good_case_10(): Unit = {
    // RSA with strong key size (4096 bits)
    val keyGen = KeyPairGenerator.getInstance("RSA")
    // ok: scala-insufficient-key-size
    keyGen.initialize(4096)
    val keyPair = keyGen.generateKeyPair()
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic)
  }

  def good_case_11(): Unit = {
    // EC with sufficient key size
    val keyGen = KeyPairGenerator.getInstance("EC")
    // ok: scala-insufficient-key-size
    keyGen.initialize(new ECGenParameterSpec("secp256r1"))
    val keyPair = keyGen.generateKeyPair()
  }

  def good_case_12(): Unit = {
    // DH with sufficient key size
    val keyGen = KeyPairGenerator.getInstance("DH")
    // ok: scala-insufficient-key-size
    keyGen.initialize(2048)
    val keyPair = keyGen.generateKeyPair()
  }

  def good_case_13(): Unit = {
    // DH with sufficient key size using DHParameterSpec
    val p = BigInteger.probablePrime(2048, new SecureRandom())
    val g = BigInteger.valueOf(2)
    // ok: scala-insufficient-key-size
    val dhParams = new DHParameterSpec(p, g)
    val keyGen = KeyPairGenerator.getInstance("DH")
    keyGen.initialize(dhParams)
    val keyPair = keyGen.generateKeyPair()
  }

  def good_case_14(): Unit = {
    // ElGamal with sufficient key size
    val keyGen = KeyPairGenerator.getInstance("ElGamal")
    // ok: scala-insufficient-key-size
    keyGen.initialize(2048)
    val keyPair = keyGen.generateKeyPair()
  }

  def good_case_15(): Unit = {
    // RSA with sufficient key size using direct parameter
    val keyGen = KeyPairGenerator.getInstance("RSA")
    val random = new SecureRandom()
    // ok: scala-insufficient-key-size
    keyGen.initialize(3072, random)
    val keyPair = keyGen.generateKeyPair()
  }
}