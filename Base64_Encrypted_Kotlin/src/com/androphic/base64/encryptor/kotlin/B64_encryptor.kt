import java.util.Arrays

class B64Encryptor {
	private val iB64Code = CharArray(65)
	private val iB64Index = IntArray(65)
	private var bB64Initialized = false
	private var bB64ToGlue = false

	private fun mb64_int(ch: Int): Int {
		return when (ch) {
			61 -> 64
			43 -> 62
			47 -> 63
			in 48..57 -> ch + 4
			in 65..90 -> ch - 65
			in 96..123 -> (ch - 97) + 26
			else -> 255
		}
	}

	private fun mb64_rotl16(n: Int, c: Int): Int {
		return (n and 0xFFFF shl c or (n and 0xFFFF ushr (16 - c))) and 0xFFFF
	}

	private fun mb64_rotr16(n: Int, c: Int): Int {
		return (n and 0xFFFF ushr c or (n and 0xFFFF shl (16 - c))) and 0xFFFF
	}

	private fun mb64_int_from_index(ch: Int): Int {
		val iCh = mb64_int(ch)
		return if (iCh == 255) {
			255
		} else if (ch == 61) {
			64
		} else {
			iB64Index[iCh]
		}
	}

	private fun mb64_shuffle(iKey: Int) {
		var iDither = 0x5aa5
		var iK = iKey
		for (i in 0 until 64) {
			iK = mb64_rotl16(iK, 1)
			iDither = mb64_rotr16(iDither, 1)
			val iSwitchIndex = i + (iK xor iDither) % (64 - i)
			val iA = iB64Code[i]
			iB64Code[i] = iB64Code[iSwitchIndex]
			iB64Code[iSwitchIndex] = iA
		}
	}

	private fun mb64_init_tables() {
		val sB64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		bB64ToGlue = false
		bB64Initialized = false
		for (i in 0 until 64) {
			iB64Index[i] = i and 0xff
			iB64Code[i] = sB64Chars[i]
		}
		iB64Code[64] = 0.toChar()
	}

	private fun mb64_index_tables() {
		for (i in 0 until 64) {
			iB64Index[mb64_int(iB64Code[i].code)] = i
		}
	}

	fun b64_set_key_i(iKey: IntArray?, iSize: Int) {
		mb64_init_tables()
		if (iKey != null) {
			for (i in 0 until iSize) {
				mb64_shuffle(iKey[i])
			}
			mb64_index_tables()
			bB64ToGlue = true
		}
		bB64Initialized = true
	}

	fun b64_set_key_s(sKey: String) {
		mb64_init_tables()
		if (sKey.isNotEmpty()) {
			for (i in sKey.indices) {
				mb64_shuffle(0 or sKey[i].code or (sKey[i].code shl 8))
			}
			mb64_index_tables()
			bB64ToGlue = true
		}
		bB64Initialized = true
	}

	fun b64_enc_size(inSize: Int): Int {
		return ((inSize - 1) / 3) * 4 + 4
	}

	fun b64_dec_size(inSize: Int): Int {
		return (3 * inSize) / 4
	}

	fun b64_encode(input: ByteArray, inLen: Int, output: ByteArray, iTextLineLength: Int): Int {
		if (!bB64Initialized) {
			b64_set_key_i(null, 0)
		}
		var i = 0
		var j = 0
		var k = 0
		val s = IntArray(3)
		var iDitherR = 0xa55a
		var iDitherL = 0x55aa
		var iG: Int
		var iTextLineCount = 0
		var iTextLineLengthVar = iTextLineLength
		iTextLineLengthVar = (iTextLineLengthVar / 4) * 4
		while (i < inLen) {
			if (bB64ToGlue) {
				iG = ((input[i].toInt() xor iDitherL and 0xff) and 0xff)
				s[j] = iG
				iDitherR = mb64_rotr16(iDitherR, 1) xor iG
				iDitherL = mb64_rotl16(iDitherL, 1) xor iDitherR
			} else {
				s[j] = input[i].toInt()
			}
			++j
			if (j == 3) {
				output[k + 0] = iB64Code[(s[0] and 255) shr 2].code.toByte()
				output[k + 1] = iB64Code[((s[0] and 0x03) shl 4) or ((s[1] and 0xF0) shr 4)].code.toByte()
				output[k + 2] = iB64Code[((s[1] and 0x0F) shl 2) or ((s[2] and 0xC0) shr 6)].code.toByte()
				output[k + 3] = iB64Code[s[2] and 0x3F].code.toByte()
				j = 0
				k += 4
				if (iTextLineLengthVar > 0) {
					iTextLineCount += 4
					if (iTextLineCount >= iTextLineLengthVar) {
						output[k] = '\n'.code.toByte()
						++k
						iTextLineCount = 0
					}
				}
			}
			i++
		}
		if (j != 0) {
			if (j == 1) {
				s[1] = 0
			}
			output[k + 0] = iB64Code[(s[0] and 255) shr 2].code.toByte()
			output[k + 1] = iB64Code[((s[0] and 0x03) shl 4) or ((s[1] and 0xF0) shr 4)].code.toByte()
			if (j == 2) {
				output[k + 2] = iB64Code[((s[1] and 0x0F) shl 2)].code.toByte()
			} else {
				output[k + 2] = '='.code.toByte()
			}
			output[k + 3] = '='.code.toByte()
			k += 4
			if (iTextLineLengthVar > 0) {
				iTextLineCount += 4
				if (iTextLineCount >= iTextLineLengthVar) {
					output[k] = '\n'.code.toByte()
					++k
					//iTextLineCount = 0
				}
			}
		}
		output[k] = '\u0000'.code.toByte()
		return k
	}

	fun b64_decode(input: ByteArray, inLen: Int, output: ByteArray): Int {
		if (!bB64Initialized) {
			b64_set_key_i(null, 0)
		}
		var j = 0
		var k = 0
		val s = IntArray(4)
		var iDitherR = 0xa55a
		var iDitherL = 0x55aa
		var iG: Int
		var i: Int
		i = 0
		while (i < inLen) {
			s[j] = mb64_int_from_index(input[i].toInt())
			if (s[j] != 255) {
				++j
				if (j == 4) {
					if (s[1] != 64) {
						output[k + 0] =
							(((s[0] and 255) shl 2) or ((s[1] and 0x30) shr 4)).toByte()
						if (s[2] != 64) {
							output[k + 1] =
								(((s[1] and 0x0F) shl 4) or ((s[2] and 0x3C) shr 2)).toByte()
							if (s[3] != 64) {
								output[k + 2] = (((s[2] and 0x03) shl 6) or (s[3])).toByte()
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
			}
			i++
		}
		if (bB64ToGlue) {
			for (i1 in 0 until k) {
				iG = output[i1].toInt() and 0xff
				output[i1] = ((output[i1].toInt() xor (iDitherL and 0xff)) and 0xff).toByte()
				iDitherR = mb64_rotr16(iDitherR, 1) xor iG
				iDitherL = mb64_rotl16(iDitherL, 1) xor iDitherR
			}
		}
		output[k] = '\u0000'.code.toByte()
		return k
	}

	companion object {
		@JvmStatic
		public fun main() {
			val o = B64Encryptor()
			println("B64 encryptor demonstration")
			for (i in 0 until 32) {
				print(" " + o.mb64_rotl16(0xa5, i) + ", ")
			}
			println()
			for (i in 0 until 32) {
				print(" " + o.mb64_rotr16(0xa5, i) + ", ")
			}
			println()
			val sTest =
				"000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov."
					.toByteArray()
			var sBufferDe = ByteArray(256)
			var sBufferEn = ByteArray(256 * 4 / 3 + 1)
			//var iEncodedSize = 0
			//var iDecodedSize = 0
			var iSourceSize = sTest.size
			val iCryptKey = intArrayOf(128, 12345, 67890)

			println("Plain text: " + String(sTest))
			println(iSourceSize)
			println("-----------------------------------------------------------------------")
			println("Standard Base64 encoding")
			o.b64_set_key_i(null, 0)
			println("B64 code table: " + Arrays.toString(o.iB64Code))
			println("B64 code index table: " + Arrays.toString(o.iB64Index))
			var iEncodedSize = o.b64_encode(sTest, sTest.size, sBufferEn, 16)
			println("Standard Base64 encoded text:")
			println(String(sBufferEn))
			println(iEncodedSize)
			var iDecodedSize = o.b64_decode(sBufferEn, iEncodedSize, sBufferDe)
			println("Standard Base64 decoded text:")
			println(String(sBufferDe))
			println(iDecodedSize)
			println("-----------------------------------------------------------------------")
			sBufferDe = ByteArray(256)
			sBufferEn = ByteArray(256 * 4 / 3 + 1)
			println("Encryption with int[] as key: " + Arrays.toString(iCryptKey))
			o.b64_set_key_i(iCryptKey, iCryptKey.size)
			println("B64 code table: " + Arrays.toString(o.iB64Code))
			println("B64 code index table: " + Arrays.toString(o.iB64Index))
			iEncodedSize = o.b64_encode(sTest, sTest.size, sBufferEn, 32)
			println("Encrypted text:")
			println(String(sBufferEn))
			println(iEncodedSize)
			iDecodedSize = o.b64_decode(sBufferEn, iEncodedSize, sBufferDe)
			println("Decrypted text:")
			println(String(sBufferDe))
			println(iDecodedSize)
			println("-----------------------------------------------------------------------")
			sBufferDe = ByteArray(256)
			sBufferEn = ByteArray(256 * 4 / 3 + 1)
			println("Encryption with String as key: " + "ThisIsTheKey1")
			o.b64_set_key_s("ThisIsTheKey1")
			println("B64 code table: " + Arrays.toString(o.iB64Code))
			println("B64 code index table: " + Arrays.toString(o.iB64Index))
			iEncodedSize = o.b64_encode(sTest, sTest.size, sBufferEn, 64)
			println("Encrypted text:")
			println(String(sBufferEn))
			println(iEncodedSize)
			iDecodedSize = o.b64_decode(sBufferEn, iEncodedSize, sBufferDe)
			println("Decrypted text:")
			println(String(sBufferDe))
			println(iDecodedSize)
			println("-----------------------------------------------------------------------")
			sBufferDe = ByteArray(256)
			sBufferEn = ByteArray(256 * 4 / 3 + 1)
			println("Encryption with int[0] as key: " + iCryptKey[0])
			o.b64_set_key_i(iCryptKey, 1)
			println("B64 code table: " + Arrays.toString(o.iB64Code))
			println("B64 code index table: " + Arrays.toString(o.iB64Index))
			iEncodedSize = o.b64_encode(sTest, sTest.size, sBufferEn, 80)
			println("Encrypted text:")
			println(String(sBufferEn))
			println(iEncodedSize)
			iDecodedSize = o.b64_decode(sBufferEn, iEncodedSize, sBufferDe)
			println("Decrypted text:")
			println(String(sBufferDe))
			println(iDecodedSize)
			println("-----------------------------------------------------------------------")

			val iTS = System.currentTimeMillis().toInt()
			val iExperiments: Long = 123456
			var iProgressPrev = 0
			var iProgress: Int
			var iMsgSize: Int
			for (i in 0 until iExperiments) {
				iMsgSize = (i % 256).toInt()
				iCryptKey[0] = System.currentTimeMillis().toInt()
				iCryptKey[1] = System.currentTimeMillis().toInt()
				iCryptKey[2] = System.currentTimeMillis().toInt()
				o.b64_set_key_i(iCryptKey, iCryptKey.size)
				for (i1 in 0 until iMsgSize) {
					sBufferDe[i1] = (i1 + i).toByte()
				}
				iEncodedSize = o.b64_encode(sBufferDe, iMsgSize, sBufferEn, 0)
				iDecodedSize = o.b64_decode(sBufferEn, iEncodedSize, sBufferDe)
				for (i1 in 0 until iMsgSize) {
					if (sBufferDe[i1] != (i1 + i).toByte()) {
						println("ERR: $i, ${String(sBufferEn)}")
						return
					}
				}
				iProgress = (i * 100 / iExperiments).toInt()
				if (iProgressPrev != iProgress) {
					println("Progress: $iProgress%, ${String(sBufferEn).split(0.toChar())[0]}, $iDecodedSize")
					iProgressPrev = iProgress
				}
			}
			println("Time (millis): " + (System.currentTimeMillis().toInt() - iTS))
		}
	}
}

fun main() {
	B64Encryptor.main()
}