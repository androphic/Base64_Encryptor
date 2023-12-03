/*
 ============================================================================
 Name        : B64Encryptor.java
 Author      : Tofig Kareemov
 Version     :
 Copyright   : Your copyright notice
 Description : Base64 Encryptor in Java
 ============================================================================
 */
package com.androphic.base64.encryptor;

import java.util.Arrays;

public class B64Encryptor {
	public static final String S_ALPHABET_STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	public static final String S_ALPHABET_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
	public static final String S_ALPHABET_QWERTY = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890-_=";
	public static final String S_ALPHABET_IMAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,=";
	public static final String S_ALPHABET_HQX = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr=";
	public static final String S_ALPHABET_CRYPT = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=";
	public static final String S_ALPHABET_GEDCOM = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=";
	public static final String S_ALPHABET_BCRYPT = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=";
	public static final String S_ALPHABET_XX = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=";
	public static final String S_ALPHABET_BASH = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@_=";

	public static final int I_LENGTH_STANDARD = 0;
	public static final int I_LENGTH_MIME = 76;
	public static final int I_LENGTH_PEM = 64;

	private char[] cAlphabet = new char[65];
	private final int[] iAlphabetIndex = new int[128];
	private boolean bInitialized = false;
	private boolean bToGlue = false;

	private class State {
		int iOutLen = 0; // Output Lenght
		int[] iBuf = new int[4]; // Processing group buffer
		int iB = 0; // Processing group index
		int iDR = 0xa55a; // Dither rotating right
		int iDL = 0x55aa; // Dither rotating left
		int iG = 0; // Glue
		int iLineLen = 0; // Current text line length

		private void init() {
			iOutLen = 0;
			iBuf[0] = 0;
			iBuf[1] = 0;
			iBuf[2] = 0;
			iBuf[3] = 0;
			iB = 0;
			iDR = 0xa55a;
			iDL = 0x55aa;
			iG = 0;
			iLineLen = 0;
		}
	}

	private State oEncState = new State();
	private State oDecState = new State();

//	private int decodeB64Char(int ch) {
//		//!!! Make it generic to support any Alphabet
//		if ((ch > 64) && (ch < 91)) {
//			return ch - 'A';
//		} else if ((ch > 96) && (ch < 123)) {
//			return (ch - 'a') + 26;
//		} else if ((ch > 47) && (ch < 58)) {
//			return ch + 4;
//		} else if ((ch == '+') || (ch == '-')) {
//			return 62;
//		} else if ((ch == '/') || (ch == '_')) {
//			return 63;
//		} else if (ch == 61) {
//			return 64;
//		}
//		return 255;
//		//!!!
//	}

	private int rotl16(int n, int c) {
		n = n & 0xFFFF;
		c &= 15;
		return ((n << c) | (n >> (16 - c))) & 0xFFFF;
	}

	private int rotr16(int n, int c) {
		n = n & 0xFFFF;
		c &= 15;
		return ((n >> c) | (n << (16 - c))) & 0xFFFF;
	}

	private void shuffleCodeTable(int iKey) {
		int iDitherForKey = 0x5aa5;
		for (int i = 0; i < 64; ++i) {
			iKey = rotl16(iKey, 1);
			iDitherForKey = rotr16(iDitherForKey, 1);
			int iSwitchIndex = i + (iKey ^ iDitherForKey) % (64 - i);
			char iA = cAlphabet[i];
			cAlphabet[i] = cAlphabet[iSwitchIndex];
			cAlphabet[iSwitchIndex] = iA;
		}
	}

	private void setAlphabet(String sAlphabet) {
		if ((sAlphabet == null) || (sAlphabet.length() != 65)) {
			cAlphabet = S_ALPHABET_STANDARD.toCharArray();
			return;
		}
		cAlphabet = sAlphabet.toCharArray();
		for (int i = 0; i < iAlphabetIndex.length; ++i) {
			iAlphabetIndex[i] = 0;
		}
		for (int i = 0; i < cAlphabet.length; ++i) {
			cAlphabet[i] = (char) (cAlphabet[i] & 0x7f);
			if (iAlphabetIndex[cAlphabet[i]] == 0) {
				iAlphabetIndex[cAlphabet[i]] = 1;
			} else {
				cAlphabet = S_ALPHABET_STANDARD.toCharArray();
				return;
			}
		}
	}

	private void initTables(String sAlphabet) {
		bToGlue = false;
		bInitialized = false;
		oEncState.init();
		oDecState.init();
		setAlphabet(sAlphabet);
	}

	private void indexTables() {
		for (int i = 0; i < iAlphabetIndex.length; ++i) {
			iAlphabetIndex[i] = 255;
		}
		for (int i = 0; i < cAlphabet.length; ++i) {
			iAlphabetIndex[cAlphabet[i]] = i;
		}
	}

	public void setEncryption(int[] iKey, int iKeyLength, String sAlphabet) {
		initTables(sAlphabet);
		if (iKey != null) {
			if ((iKeyLength <= 0) || (iKeyLength > iKey.length)) {
				iKeyLength = iKey.length;
			}
			for (int i = 0; i < iKeyLength; ++i) {
				shuffleCodeTable(iKey[i]);
			}
			bToGlue = true;
		}
		indexTables();
		bInitialized = true;
	}

	public void setEncryption(String sKey, String sAlphabet) {
		initTables(sAlphabet);
		if (sKey != null) {
			for (int i = 0; i < sKey.length(); ++i) {
				shuffleCodeTable(0 | sKey.charAt(i) | (sKey.charAt(i) << 8));
			}
			indexTables();
			bToGlue = true;
		}
		bInitialized = true;
	}

	public int calcEncryptedLen(int iInputLen, int iLineLength, boolean bPadding) {
		iLineLength = (iLineLength / 4) * 4;
		int iOutputLen = iInputLen / 3 * 4;
		if (iLineLength > 0) {
			iOutputLen = (iOutputLen + (iOutputLen / iLineLength * 2));
		}
		if (iInputLen % 3 == 1) {
			iOutputLen += 2;
			if (bPadding) {
				iOutputLen += 2;
			}
		} else if (iInputLen % 3 == 2) {
			iOutputLen += 3;
			if (bPadding) {
				iOutputLen += 1;
			}
		}
		return iOutputLen;
	}

	public int calcDecryptedLen(int iInputSize, int iLineLength, boolean bPadding) {
		iLineLength = (iLineLength / 4) * 4;
		int iOutputLen;
		if (iLineLength > 0) {
			iInputSize = iInputSize - (iInputSize / (iLineLength + 2)) * 2;
		}
		iOutputLen = (iInputSize / 4) * 3;
		if (!bPadding) {
			if (iInputSize % 4 == 2) {
				iOutputLen = iOutputLen + 1;
			} else if (iInputSize % 4 == 3) {
				iOutputLen = iOutputLen + 2;
			}
		} else {
		}
		return iOutputLen;
	}

	public int encrypt(byte[] iIn, int iInLen, byte[] iOut, int iLineMaxLen, boolean bPadding) {
		if (!bInitialized) {
			setEncryption(null, 0, null);
		}
		iLineMaxLen = (iLineMaxLen / 4) * 4;
		State o = oEncState;
		for (int i = 0; i < iInLen; i++) {
			if (bToGlue) {
				o.iG = ((iIn[i] ^ o.iDL & 0xff) & 0xff);
				o.iBuf[o.iB] = o.iG;
				o.iDR = rotr16(o.iDR, 1) ^ o.iG;
				o.iDL = rotl16(o.iDL, 1) ^ o.iDR;
			} else {
				o.iBuf[o.iB] = (byte) (iIn[i]);
			}
			++o.iB;
			if (o.iB == 3) {
				iOut[o.iOutLen + 0] = (byte) cAlphabet[(o.iBuf[0] & 255) >> 2];
				iOut[o.iOutLen + 1] = (byte) cAlphabet[((o.iBuf[0] & 0x03) << 4) | ((o.iBuf[1] & 0xF0) >> 4)];
				iOut[o.iOutLen + 2] = (byte) cAlphabet[((o.iBuf[1] & 0x0F) << 2) | ((o.iBuf[2] & 0xC0) >> 6)];
				iOut[o.iOutLen + 3] = (byte) cAlphabet[o.iBuf[2] & 0x3F];
				o.iB = 0;
				o.iOutLen += 4;
				if (iLineMaxLen > 0) {
					o.iLineLen += 4;
					if (o.iLineLen >= iLineMaxLen) {
						iOut[o.iOutLen] = '\r';
						++o.iOutLen;
						iOut[o.iOutLen] = '\n';
						++o.iOutLen;
						o.iLineLen = 0;
					}
				}
			}
		}
		if (o.iB != 0) {
			if (o.iB == 1) {
				o.iBuf[1] = 0;
			}
			iOut[o.iOutLen + 0] = (byte) cAlphabet[(o.iBuf[0] & 255) >> 2];
			iOut[o.iOutLen + 1] = (byte) cAlphabet[((o.iBuf[0] & 0x03) << 4) | ((o.iBuf[1] & 0xF0) >> 4)];
			o.iOutLen += 2;
			if (o.iB == 2) {
				iOut[o.iOutLen] = (byte) cAlphabet[((o.iBuf[1] & 0x0F) << 2)];
				++o.iOutLen;
			} else {
				if (bPadding) {
					iOut[o.iOutLen] = (byte) (cAlphabet[64] % 0xff);
					++o.iOutLen;
				}
			}
			if (bPadding) {
				iOut[o.iOutLen] = (byte) (cAlphabet[64] % 0xff);
				++o.iOutLen;
			}
		}
		iOut[o.iOutLen] = '\0';
		return o.iOutLen;
	}

	public int decrypt(byte[] in, int in_len, byte[] out) {
		State o = oDecState;
		if (!bInitialized) {
			setEncryption(null, 0, null);
		}
		for (int i = 0; i < in_len; ++i) {
			o.iBuf[o.iB] = iAlphabetIndex[in[i]];
			if (o.iBuf[o.iB] != 255) {
				++o.iB;
				if (o.iB == 4) {
					if (o.iBuf[1] != 64) {
						out[o.iOutLen + 0] = (byte) (((o.iBuf[0] & 255) << 2) | ((o.iBuf[1] & 0x30) >> 4));
						if (o.iBuf[2] != 64) {
							out[o.iOutLen + 1] = (byte) (((o.iBuf[1] & 0x0F) << 4) | ((o.iBuf[2] & 0x3C) >> 2));
							if (o.iBuf[3] != 64) {
								out[o.iOutLen + 2] = (byte) (((o.iBuf[2] & 0x03) << 6) | (o.iBuf[3]));
								o.iOutLen += 3;
							} else {
								o.iOutLen += 2;
							}
						} else {
							o.iOutLen += 1;
						}
					}
					o.iB = 0;
				}
			}
		}
		if (o.iB >= 2) {
			out[o.iOutLen] = (byte) (((o.iBuf[0] & 255) << 2) | ((o.iBuf[1] & 0x30) >> 4));
			++o.iOutLen;
		}
		if (o.iB == 3) {
			out[o.iOutLen] = (byte) (((o.iBuf[1] & 0x0F) << 4) | ((o.iBuf[2] & 0x3C) >> 2));
			++o.iOutLen;
		}
		if (bToGlue) {
			for (int i = 0; i < o.iOutLen; ++i) {
				o.iG = out[i] & 0xff;
				out[i] = (byte) ((out[i] ^ o.iDL & 0xff) & 0xff);
				o.iDR = rotr16(o.iDR, 1) ^ o.iG;
				o.iDL = rotl16(o.iDL, 1) ^ o.iDR;
			}
		}
		out[o.iOutLen] = '\0';
		return o.iOutLen;
	}

	public static void main(String[] args) {
		B64Encryptor o = new B64Encryptor();
		System.out.println("B64 encryptor demonstration");
		for (int i = 0; i < 32; ++i) {
			System.out.print(" " + o.rotl16(0xa5, i) + ", ");
		}
		System.out.println();
		for (int i = 0; i < 32; ++i) {
			System.out.print(" " + o.rotr16(0xa5, i) + ", ");
		}
		System.out.println();
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
		iEncodedLen = o.encrypt(sTest, sTest.length, sBufferEn, I_LENGTH_PEM, false);
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
		iEncodedLen = o.encrypt(sTest, sTest.length, sBufferEn, I_LENGTH_MIME, false);
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
			for (int i1 = 0; i1 < iMsgSize; ++i1) {
				sBufferDe[i1] = (byte) (i1 + i);
			}
			int iLineLength = (iCryptKey[1] & 0x3f);
			boolean bPadding = (iCryptKey[2] & 1) == 1;
			iEncodedLen = o.encrypt(sBufferDe, iMsgSize, sBufferEn, iLineLength, bPadding);
			iDecodedLen = o.decrypt(sBufferEn, iEncodedLen, sBufferDe);
			int iCalc = o.calcEncryptedLen(iMsgSize, iLineLength, bPadding);
			if (iCalc != iEncodedLen) {
				System.out.println("ERR: Enc size calc is not correct, expected " + iCalc + "( " + iMsgSize + ", "
						+ iLineLength + ", " + bPadding + ")" + ", real " + iEncodedLen);
				return;
			}
			iCalc = o.calcDecryptedLen(iEncodedLen, iLineLength, bPadding);
			if (!((iCalc >= iDecodedLen) && (iCalc < iDecodedLen + 3))) {
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
