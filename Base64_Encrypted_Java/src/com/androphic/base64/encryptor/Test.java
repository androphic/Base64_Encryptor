package com.androphic.base64.encryptor;

import java.util.Arrays;

public class Test extends C64{
	public static void main(String[] args) {
		C64 o = new C64();
		System.out.println("B64 encryptor demonstration");
		for (int i = 0; i < 32; ++i) {
			System.out.print(" " + o.rotl16(0xa5, i) + ", ");
		}
		System.out.println();
		for (int i = 0; i < 32; ++i) {
			System.out.print(" " + o.rotr16(0xa5, i) + ", ");
		}
		System.out.println("-----------------------------------------------------------------------");
		byte[] sTest = "000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov."
				.getBytes();
		byte[] sBufferDe = new byte[256];
		byte[] sBufferEn = new byte[256 * 2];
		int iSourceSize = 0;
		int iEncodedLen = 0;
		int iDecodedLen = 0;
		iSourceSize = sTest.length;
		int[] iCryptKey = new int[] { 128, 12345, 67890 };
		System.out.println("Plain text: " + new String(sTest));
		System.out.println(iSourceSize);
		System.out.println("-----------------------------------------------------------------------");
		System.out.println("Standard Base64 encoding");
		o.setEncryption(null, 0, S_ALPHABET_STANDARD);
		System.out.println("B64 code table: " + Arrays.toString(o.cAlphabet));
		System.out.println("B64 code index table: " + Arrays.toString(o.iAlphabetIndex));
		iEncodedLen = o.encrypt(sTest, sTest.length, sBufferEn, 17, true);
		System.out.println("Standard Base64 encoded text:");
		System.out.println(new String(sBufferEn));
		System.out.println(iEncodedLen);
		iDecodedLen = o.decrypt(sBufferEn, iEncodedLen, sBufferDe);
		System.out.println("Standard Base64 decoded text:");
		System.out.println(new String(sBufferDe));
		System.out.println(iDecodedLen);
		System.out.println("-----------------------------------------------------------------------");
		sBufferDe = new byte[256];
		sBufferEn = new byte[256 * 4 / 3 + 1];
		System.out.println("Encryption with int[] as key: " + Arrays.toString(iCryptKey));
		o.setEncryption(iCryptKey, iCryptKey.length, S_ALPHABET_URL);
		System.out.println("B64 code table: " + Arrays.toString(o.cAlphabet));
		System.out.println("B64 code index table: " + Arrays.toString(o.iAlphabetIndex));
		iEncodedLen = o.encrypt(sTest, sTest.length, sBufferEn, I_LINE_PEM, false);
		System.out.println("Encrypted text:");
		System.out.println(new String(sBufferEn));
		System.out.println(iEncodedLen);
		iDecodedLen = o.decrypt(sBufferEn, iEncodedLen, sBufferDe);
		System.out.println("Decrypted text:");
		System.out.println(new String(sBufferDe));
		System.out.println(iDecodedLen);
		System.out.println("-----------------------------------------------------------------------");
		sBufferDe = new byte[256];
		sBufferEn = new byte[256 * 4 / 3 + 1];
		System.out.println("Encryption with String as key: " + "ThisIsTheKey1");
		o.setEncryption("ThisIsTheKey1", S_ALPHABET_QWERTY);
		System.out.println("B64 code table: " + Arrays.toString(o.cAlphabet));
		System.out.println("B64 code index table: " + Arrays.toString(o.iAlphabetIndex));
		iEncodedLen = o.encrypt(sTest, sTest.length, sBufferEn, I_LINE_MIME, false);
		System.out.println("Encrypted text:");
		System.out.println(new String(sBufferEn));
		System.out.println(iEncodedLen);
		iDecodedLen = o.decrypt(sBufferEn, iEncodedLen, sBufferDe);
		System.out.println("Decrypted text:");
		System.out.println(new String(sBufferDe));
		System.out.println(iDecodedLen);
		System.out.println("-----------------------------------------------------------------------");
		sBufferDe = new byte[256];
		sBufferEn = new byte[256 * 4 / 3 + 1];
		System.out.println("Encryption with int[0] as key: " + iCryptKey[0]);
		o.setEncryption(iCryptKey, 1, S_ALPHABET_STANDARD);
		System.out.println("B64 code table: " + Arrays.toString(o.cAlphabet));
		System.out.println("B64 code index table: " + Arrays.toString(o.iAlphabetIndex));
		iEncodedLen = o.encrypt(sTest, sTest.length, sBufferEn, 80, true);
		System.out.println("Encrypted text:");
		System.out.println(new String(sBufferEn));
		System.out.println(iEncodedLen);
		iDecodedLen = o.decrypt(sBufferEn, iEncodedLen, sBufferDe);
		System.out.println("Decrypted text:");
		System.out.println(new String(sBufferDe));
		System.out.println(iDecodedLen);
		System.out.println("-----------------------------------------------------------------------");

		sBufferDe = new byte[256];
		sBufferEn = new byte[256 * 2];
		int iTS = (int) System.currentTimeMillis();
		long iExperiments = 1234567;
		int iProgressPrev = 0;
		int iProgress = 0;
		int iMsgSize = 80;
		for (long i = 0; i < iExperiments; ++i) {
			iMsgSize = (int) (i % 256);
			iCryptKey[0] = (int) System.currentTimeMillis();
			iCryptKey[1] = (int) System.currentTimeMillis();
			iCryptKey[2] = (int) System.currentTimeMillis();
			o.setEncryption(iCryptKey, 3, S_ALPHABET_QWERTY);
			o.resetStates();
			for (int i1 = 0; i1 < iMsgSize; ++i1) {
				sBufferDe[i1] = (byte) (i1 + i);
			}
			int iLineLength = (iCryptKey[1] & 0x3f);
			boolean bPadding = (iCryptKey[2] & 1) == 1;
			iEncodedLen = o.encrypt(sBufferDe, iMsgSize, sBufferEn, iLineLength, bPadding);
			iDecodedLen = o.decrypt(sBufferEn, iEncodedLen, sBufferDe);
			int iCalc = o.calcEncryptedLen(iMsgSize, iLineLength, bPadding);
			if (iCalc != (iEncodedLen)) {
				System.out.println("ERR: Enc size calc is not correct, expected " + iCalc + "( " + iMsgSize + ", "
						+ iLineLength + ", " + bPadding + ")" + ", real " + iEncodedLen);
				return;
			}
			iCalc = o.calcDecryptedLen(iEncodedLen, iLineLength, bPadding);
			if (!((iCalc >= iDecodedLen) && (iCalc < (iDecodedLen + 3)))) {
				System.out.println("ERR: Dec size calc is not correct, expected " + iCalc + "( " + iEncodedLen + ", "
						+ iLineLength + ", " + bPadding + ")" + ", real " + iDecodedLen);
				return;
			}
			for (int i1 = 0; i1 < iMsgSize; ++i1) {
				if (sBufferDe[i1] != (byte) (i1 + i)) {
					System.out.println("ERR: " + i + ", " + new String(sBufferEn));
					return;
				}
			}
			iProgress = (int) (i * 100 / iExperiments);
			if (iProgressPrev != iProgress) {
				System.out.println("Progress: " + iProgress + "%, " + new String(sBufferEn).split("\0")[0]);
				iProgressPrev = iProgress;
			}
		}
		System.out.println("Time (millis): " + ((int) System.currentTimeMillis() - iTS));
	}

}
