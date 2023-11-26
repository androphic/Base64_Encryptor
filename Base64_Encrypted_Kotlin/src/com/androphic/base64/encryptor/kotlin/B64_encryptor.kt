package com.androphic.base64.encryptor.kotlin

import java.util.Arrays

object B64_Encryptor {
	private val b64Code = CharArray(65)
	private val b64Index = IntArray(65)
	private var bInitialized = false

	private fun b64Int(ch: Int): Int {
		return when (ch) {
			61 -> 64
			43 -> 62
			47 -> 63
			in 48..57 -> ch + 4
			in 65..90 -> ch - 'A'.toInt()
			in 96..123 -> (ch - 'a'.toInt()) + 26
			else -> 64
		}
	}

	private fun rotl16(n: Int, c: Int): Int {
		val mask = 0xFFFF
		val nc = c and 15
		return ((n shl nc) or (n ushr (16 - nc))) and mask
	}

	private fun rotr16(n: Int, c: Int): Int {
		val mask = 0xFFFF
		val nc = c and 15
		return ((n ushr nc) or (n shl (16 - nc))) and mask
	}

	private fun b64IntFromIndex(ch: Int): Int {
		return if (ch == 61) {
			64
		} else {
			b64Index[b64Int(ch)]
		}
	}

	private fun b64Shuffle(iKey: Int) {
		var iKeyVar = iKey
		var iDither = 0x5aa5
		for (i in 0 until 64) {
			iKeyVar = rotl16(iKeyVar, 1)
			iDither = rotr16(iDither, 1)
			val iSwitchIndex = i + (iKeyVar xor iDither) % (64 - i)
			val iA = b64Code[i]
			b64Code[i] = b64Code[iSwitchIndex]
			b64Code[iSwitchIndex] = iA
		}
		for (i in 0 until 64) {
			b64Index[b64Int(b64Code[i].code)] = i
		}
	}

	private fun b64Init(iKey: Int) {
		val sB64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		for (i in 0 until 64) {
			b64Index[i] = i and 0xff
			b64Code[i] = sB64Chars[i]
		}
		b64Code[64] = 64.toChar()
		b64Shuffle(iKey)
		bInitialized = true
	}

	private fun b64eSize(inSize: Int): Int {
		return ((inSize - 1) / 3) * 4 + 4
	}

	private fun b64dSize(inSize: Int): Int {
		return (3 * inSize) / 4
	}

	private fun b64Encode(input: ByteArray, inLen: Int, output: ByteArray): Int {
		if (!bInitialized) {
			b64Init(0)
		}
		var i = 0
		var j = 0
		var k = 0
		val s = IntArray(3)
		var iDither = 0xa55a
		var iG: Int
		while (i < inLen) {
			iG = (input[i].toInt() xor (iDither and 0xff)) and 0xff
			s[j] = iG
			j++
			iDither = rotr16(iDither, 1) xor iG
			if (j == 3) {
				output[k + 0] = b64Code[(s[0] and 255) ushr 2].toByte()
				output[k + 1] = b64Code[((s[0] and 0x03) shl 4) or ((s[1] and 0xF0) ushr 4)].toByte()
				output[k + 2] = b64Code[((s[1] and 0x0F) shl 2) or ((s[2] and 0xC0) ushr 6)].toByte()
				output[k + 3] = b64Code[s[2] and 0x3F].toByte()
				j = 0
				k += 4
			}
			i++
		}
		if (j != 0) {
			if (j == 1) {
				s[1] = 0
			}
			output[k + 0] = b64Code[(s[0] and 255) ushr 2].toByte()
			output[k + 1] = b64Code[((s[0] and 0x03) shl 4) or ((s[1] and 0xF0) ushr 4)].toByte()
			if (j == 2) {
				output[k + 2] = b64Code[((s[1] and 0x0F) shl 2)].toByte()
			} else {
				output[k + 2] = '='.toByte()
			}
			output[k + 3] = '='.toByte()
			k += 4
		}
		output[k] = 0.toByte()
		return k
	}

	private fun b64Decode(input: ByteArray, inLen: Int, output: ByteArray): Int {
		if (!bInitialized) {
			b64Init(0)
		}
		var j = 0
		var k = 0
		val s = IntArray(4)
		var iDither = 0xa55a
		var iG: Int
		var i = 0
		while (i < inLen) {
			s[j++] = b64IntFromIndex(input[i].toInt())
			if (j == 4) {
				if (s[1] != 64) {
					output[k + 0] = (((s[0] and 255) shl 2) or ((s[1] and 0x30) ushr 4)).toByte()
					if (s[2] != 64) {
						output[k + 1] = (((s[1] and 0x0F) shl 4) or ((s[2] and 0x3C) ushr 2)).toByte()
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
			i++
		}
		for (i in 0 until k) {
			iG = output[i].toInt() and 0xff
			output[i] = ((output[i].toInt() xor (iDither and 0xff)) and 0xff).toByte()
			iDither = rotr16(iDither, 1) xor iG
		}
		output[k] = 0.toByte()
		return k
	}

	@JvmStatic
	fun main() {
		println("B64 encryptor demonstration")
		for (i in 0 until 32) {
			print(" " + rotl16(0xa5, i) + ", ")
		}
		println()
		for (i in 0 until 32) {
			print(" " + rotr16(0xa5, i) + ", ")
		}
		println()

		val iCryptKey = 128 // System.currentTimeMillis().toInt()
		b64Init(iCryptKey)
		println("Crypt key: 0x" + Integer.toHexString(iCryptKey))
		println("B64 code table: " + Arrays.toString(b64Code))
		println("B64 code index table: " + Arrays.toString(b64Index))
		val sTest =
			"000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.".toByteArray()
		val sBufferDe = ByteArray(256)
		val sBufferEn = ByteArray(256 * 4 / 3 + 1)
		var iSourceSize: Int
		var iEncodedSize: Int
		var iDecodedSize: Int
		iSourceSize = sTest.size
		println("Plain text: " + String(sTest))
		println(iSourceSize)
		iEncodedSize = b64Encode(sTest, sTest.size, sBufferEn)
		println("Crypt text: " + String(sBufferEn))
		println(iEncodedSize)
		iDecodedSize = b64Decode(sBufferEn, iEncodedSize, sBufferDe)
		println("Decrypt text: " + String(sBufferDe))
		println(iDecodedSize)
		val iTS = System.currentTimeMillis().toInt()
		val iExperiments: Long = 12345
		var iProgressPrev = 0
		var iProgress: Int
		var iMsgSize = 80
		var i1: Int
		for (i in 0 until iExperiments) {
			iMsgSize = (i % 256).toInt()
			val iCryptKeyVar = System.currentTimeMillis().toInt()
			b64Init(iCryptKeyVar)
			for (i1 in 0 until iMsgSize) {
				sBufferDe[i1] = (i1 + i).toByte()
			}
			iEncodedSize = b64Encode(sBufferDe, iMsgSize, sBufferEn)
			iDecodedSize = b64Decode(sBufferEn, iEncodedSize, sBufferDe)
			for (i1 in 0 until iMsgSize) {
				if (sBufferDe[i1] != (i1 + i).toByte()) {
					println("ERR: $i, ${String(sBufferEn)}")
					return
				}
			}
			iProgress = (i * 100 / iExperiments).toInt()
			if (iProgressPrev != iProgress) {
				println("Progress: $iProgress%, ${String(sBufferEn).split(0.toChar())[0]}")
				iProgressPrev = iProgress
			}
		}
		println("Time (millis): " + (System.currentTimeMillis().toInt() - iTS))
	}
}

fun main(){
	B64_Encryptor.main()
}