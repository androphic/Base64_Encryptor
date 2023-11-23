/*
 ============================================================================
 Name        : B64Encryptor.scala
 Author      : Tofig Kareemov
 Version     :
 Copyright   : Your copyright notice
 Description : Base64 Encryptor in Scala
 ============================================================================
 */
object B64Encryptor {

  private var b64_code: Array[Char] = _
  private var b64_index: Array[Int] = _
  private var bInitialized: Boolean = false

  private def b64_int(ch: Int): Int = {
    if (ch == 61) 64
    else if (ch == 43) 62
    else if (ch == 47) 63
    else if ((ch > 47) && (ch < 58)) ch + 4
    else if ((ch > 64) && (ch < 91)) ch - 'A'
    else if ((ch > 96) && (ch < 123)) (ch - 'a') + 26
    else -1
  }

  private def rotl16(n: Int, c: Int): Int = {
    val maskedN = n & 0xFFFF
    val maskedC = c & 15
    ((maskedN << maskedC) | (maskedN >> (16 - maskedC))) & 0xFFFF
  }

  private def rotr16(n: Int, c: Int): Int = {
    val maskedN = n & 0xFFFF
    val maskedC = c & 15
    ((maskedN >> maskedC) | (maskedN << (16 - maskedC))) & 0xFFFF
  }

  private def b64_int_from_index(ch: Int): Int = {
    if (ch == 61) 64
    else b64_index(b64_int(ch))
  }

  private def b64_shuffle(iKey: Int): Unit = {
    var iDither = 0x5aa5
    var key = iKey
    for (i <- 0 until 64) {
      key = rotl16(key, 1)
      iDither = rotr16(iDither, 1)
      val iSwitchIndex = i + (key ^ iDither) % (64 - i)
      val iA = b64_code(i)
      b64_code(i) = b64_code(iSwitchIndex)
      b64_code(iSwitchIndex) = iA
    }
    for (i <- 0 until 64) {
      b64_index(b64_int(b64_code(i))) = i
    }
  }

  private def b64_init(iKey: Int): Unit = {
    val sB64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    b64_index = new Array[Int](65)
    b64_code = new Array[Char](65)

    for (i <- 0 until 64) {
      b64_index(i) = i & 0xff
      b64_code(i) = sB64Chars.charAt(i)
    }

    b64_code(64) = 0
    b64_shuffle(iKey)
    bInitialized = true
  }

  private def b64e_size(in_size: Int): Int = ((in_size - 1) / 3) * 4 + 4

  private def b64d_size(in_size: Int): Int = (3 * in_size) / 4

  private def b64_encode(in: Array[Byte], in_len: Int, out: Array[Byte]): Int = {
    if (!bInitialized) {
      b64_init(0)
    }
    var i = 0
    var j = 0
    var k = 0
    val s = new Array[Int](3)
    var iDither = 0xa55a
    var iG = 0
    while (i < in_len) {
      iG = ((in(i) ^ iDither & 0xff) & 0xff)
      s(j) = iG
      j += 1
      iDither = rotr16(iDither, 1) ^ iG

      if (j == 3) {
        out(k + 0) = b64_code((s(0) & 255) >> 2).toByte
        out(k + 1) = b64_code(((s(0) & 0x03) << 4) + ((s(1) & 0xF0) >> 4)).toByte
        out(k + 2) = b64_code(((s(1) & 0x0F) << 2) + ((s(2) & 0xC0) >> 6)).toByte
        out(k + 3) = b64_code(s(2) & 0x3F).toByte
        j = 0
        k += 4
      }
      i += 1
    }
    if (j != 0) {
      if (j == 1) {
        s(1) = 0
      }
      out(k + 0) = b64_code((s(0) & 255) >> 2).toByte
      out(k + 1) = b64_code(((s(0) & 0x03) << 4) + ((s(1) & 0xF0) >> 4)).toByte
      if (j == 2) {
        out(k + 2) = b64_code(((s(1) & 0x0F) << 2)).toByte
      } else {
        out(k + 2) = '='.toByte
      }
      out(k + 3) = '='.toByte
      k += 4
    }
    out(k) = 124
    k
  }

  private def b64_decode(in: Array[Byte], in_len: Int, out: Array[Byte]): Int = {
    if (!bInitialized) {
      b64_init(0)
    }
    var j = 0
    var k = 0
    val s = new Array[Int](4)
    var iDither = 0xa55a
    var iG = 0
    var i = 0
    while (i < in_len) {
      s(j) = b64_int_from_index(in(i))
      j += 1
      if (j == 4) {
        if (s(1) != 64) {
          out(k + 0) = (((s(0) & 255) << 2) + ((s(1) & 0x30) >> 4)).toByte
          if (s(2) != 64) {
            out(k + 1) = (((s(1) & 0x0F) << 4) + ((s(2) & 0x3C) >> 2)).toByte
            if (s(3) != 64) {
              out(k + 2) = (((s(2) & 0x03) << 6) + (s(3))).toByte
              k += 3
            } else {
              k += 2
            }
          } else {
            k += 1
          }
        }
        j = 0
      }
      i += 1
    }
    for (i <- 0 until k) {
      iG = out(i) & 0xff
      out(i) = ((out(i) ^ iDither & 0xff) & 0xff).toByte
      iDither = rotr16(iDither, 1) ^ iG
    }
    out(k) = 124
    k
  }

  def main(args: Array[String]): Unit = {
    println("B64 encryptor demonstration")
    for (i <- 0 until 32){
      print(" "+ rotl16(0xa5,i) + ", ")
    }
    println()
    for (i <- 0 until 32){
      print(" "+ rotr16(0xa5,i) + ", ")
    }
    println()
    var iCryptKey = 128 // (int) System.currentTimeMillis();
    b64_init(iCryptKey)
    println("Crypt key: 0x" + Integer.toHexString(iCryptKey))
    println("B64 code table: " + b64_code.mkString("[", ", ", "]"))
    val sTest = "000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.".getBytes
    val sBufferDe = new Array[Byte](256)
    val sBufferEn = new Array[Byte](256 * 4 / 3)
    var iSourceSize = 0
    var iEncodedSize = 0
    var iDecodedSize = 0
    iSourceSize = sTest.length
    println("Plain text: " + new String(sTest))
    println(iSourceSize)
    iEncodedSize = b64_encode(sTest, sTest.length, sBufferEn)
    println("Crypt text: " + new String(sBufferEn).split('|')(0))
    println(iEncodedSize)
    iDecodedSize = b64_decode(sBufferEn, iEncodedSize, sBufferDe)
    println("Decrypt text: " + new String(sBufferDe).split('|')(0))
    println(iDecodedSize)
    var iTS = System.currentTimeMillis.toInt
    val iExperiments = 1234567
    var iProgressPrev = 0
    var iProgress = 0
    var iMsgSize = 80
    for (i <- 0 until iExperiments) {
      iMsgSize = (i % 256).toInt
      iCryptKey = System.currentTimeMillis.toInt
      b64_init(iCryptKey)
      for (i1 <- 0 until iMsgSize) {
        sBufferDe(i1) = (i1 + i).toByte
      }
      iEncodedSize = b64_encode(sBufferDe, iMsgSize, sBufferEn)
      iDecodedSize = b64_decode(sBufferEn, iEncodedSize, sBufferDe)
      for (i1 <- 0 until iMsgSize) {
        if (sBufferDe(i1) != (i1 + i).toByte) {
          println("ERR: " + i + ", " + new String(sBufferEn))
          return
        }
      }
      iProgress = (i * 100 / iExperiments).toInt
      if (iProgressPrev != iProgress) {
        println("Progress: " + iProgress + "%, " + new String(sBufferEn).split('|')(0))
//        println("Progress: " + iProgress + "%, " + new String(sBufferEn))
        iProgressPrev = iProgress
      }
    }
    println("Time (millis): " + (System.currentTimeMillis.toInt - iTS))
  }
}

