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
	public static final String S_ALPHABET_STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	public static final String S_ALPHABET_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	public static final String S_ALPHABET_QWERTY = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890-_";
//	public static final String S_ALPHABET_IMAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
//	public static final String S_ALPHABET_UU = " !\"#$%\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";
//	public static final String S_ALPHABET_HQX = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";
//	public static final String S_ALPHABET_CRYPT = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
//	public static final String S_ALPHABET_GEDCOM = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
//	public static final String S_ALPHABET_BCRYPT = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
//	public static final String S_ALPHABET_XX = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
//	public static final String S_ALPHABET_BASH = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@_";

	public static final int I_LENGTH_STANDARD = 0;
	public static final int I_LENGTH_MIME = 76;
	public static final int I_LENGTH_PEM = 64;

	private char[] cAlphabet = new char[64];
	private int[] iAlphabetIndex = new int[64];
	private final int[] iIndexToCheckAlphabet = new int[128];
	private boolean bInitialized = false;
	private boolean bToGlue = false;

	private int decodeB64Char(int ch) {
		if ((ch > 64) && (ch < 91)) {
			return ch - 'A';
		} else if ((ch > 96) && (ch < 123)) {
			return (ch - 'a') + 26;
		} else if ((ch > 47) && (ch < 58)) {
			return ch + 4;
		} else if ((ch == '+') || (ch == '-')) {
			return 62;
		} else if ((ch == '/') || (ch == '_')) {
			return 63;
		} else if (ch == 61) {
			return 64;
		}
		return 255;
	}

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

	private int decodeInputChar(int ch) {
		int iCh = decodeB64Char(ch);
		if (iCh == 255) {
			return 255;
		}
		if (ch == 61) {
			return 64;
		} else {
			return iAlphabetIndex[iCh];
		}
	}

	private void shuffleCodeTable(int iKey) {
		int iDither = 0x5aa5;
		for (int i = 0; i < 64; ++i) {
			iKey = rotl16(iKey, 1);
			iDither = rotr16(iDither, 1);
			int iSwitchIndex = i + (iKey ^ iDither) % (64 - i);
			char iA = cAlphabet[i];
			cAlphabet[i] = cAlphabet[iSwitchIndex];
			cAlphabet[iSwitchIndex] = iA;
		}
	}

	private void setAlphabet(String sAlphabet) {
		if ((sAlphabet == null) || (sAlphabet.length() != 64)) {
			cAlphabet = S_ALPHABET_STANDARD.toCharArray();
			return;
		}
		cAlphabet = sAlphabet.toCharArray();
		for (int i = 0; i < iIndexToCheckAlphabet.length; ++i) {
			iIndexToCheckAlphabet[i] = 0;
		}
		for (int i = 0; i < 64; ++i) {
			iIndexToCheckAlphabet[(int) cAlphabet[i] & 0x7f] = 1;
		}
		int iSum = 0;
		for (int i = 0; i < iIndexToCheckAlphabet.length; ++i) {
			iSum += iIndexToCheckAlphabet[i];
		}
		if (iSum != 64) {
			cAlphabet = S_ALPHABET_STANDARD.toCharArray();
		}
	}

	private void initTables(String sAlphabet) {
		setAlphabet(sAlphabet);
		bToGlue = false;
		bInitialized = false;
		for (int i = 0; i < 64; ++i) {
			iAlphabetIndex[i] = i & 0xff;
		}
	}

	private void indexTables() {
		for (int i = 0; i < 64; ++i) {
			iAlphabetIndex[decodeB64Char(cAlphabet[i])] = i;
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

	public int calcEncryptedLen(int iInputSize, int iLineLength) {
		if (iLineLength <= 0) {
			return (((iInputSize - 1) / 3) * 4 + 4);
		} else {
			return (((iInputSize - 1) / 3) * 4 + 4) + (iInputSize / iLineLength * 2);
		}
	}

	public int calcDecryptedLen(int iInputSize, int iLineLength) {
		if (iLineLength > 0) {
			iInputSize = iInputSize - (iInputSize / (iLineLength + 2) * 2);
		}
		return ((3 * iInputSize) / 4);
	}

	public int encrypt(byte[] in, int in_len, byte[] out, int iTextLineLength, boolean bPadding) {
		if (!bInitialized) {
			setEncryption(null, 0, null);
		}
		int i = 0, j = 0, k = 0;
		int[] s = new int[3];
		int iDitherR = 0xa55a;
		int iDitherL = 0x55aa;
		int iG = 0;
		int iTextLineCount = 0;
		iTextLineLength = (iTextLineLength / 4) * 4;
		for (i = 0; i < in_len; i++) {
			if (bToGlue) {
				iG = ((in[i] ^ iDitherL & 0xff) & 0xff);
				s[j] = iG;
				iDitherR = rotr16(iDitherR, 1) ^ iG;
				iDitherL = rotl16(iDitherL, 1) ^ iDitherR;
			} else {
				s[j] = (byte) (in[i]);
			}
			++j;
			if (j == 3) {
				out[k + 0] = (byte) cAlphabet[(s[0] & 255) >> 2];
				out[k + 1] = (byte) cAlphabet[((s[0] & 0x03) << 4) | ((s[1] & 0xF0) >> 4)];
				out[k + 2] = (byte) cAlphabet[((s[1] & 0x0F) << 2) | ((s[2] & 0xC0) >> 6)];
				out[k + 3] = (byte) cAlphabet[s[2] & 0x3F];
				j = 0;
				k += 4;
				if (iTextLineLength > 0) {
					iTextLineCount += 4;
					if (iTextLineCount >= iTextLineLength) {
						out[k] = '\r';
						++k;
						out[k] = '\n';
						++k;
						iTextLineCount = 0;
					}
				}
			}
		}
		if (j != 0) {
			if (j == 1) {
				s[1] = 0;
			}
			out[k + 0] = (byte) cAlphabet[(s[0] & 255) >> 2];
			out[k + 1] = (byte) cAlphabet[((s[0] & 0x03) << 4) | ((s[1] & 0xF0) >> 4)];
			k += 2;
			if (j == 2) {
				out[k] = (byte) cAlphabet[((s[1] & 0x0F) << 2)];
				++k;
			} else {
				if (bPadding) {
					out[k] = '=';
					++k;
				}
			}
			if (bPadding) {
				out[k] = '=';
				++k;
			}
			if (iTextLineLength > 0) {
				iTextLineCount += 4;
				if (iTextLineCount >= iTextLineLength) {
					out[k] = '\r';
					++k;
					out[k] = '\n';
					++k;
//					iTextLineCount = 0;
				}
			}
		}
		out[k] = '\0';
		return k;
	}

	public int decrypt(byte[] in, int in_len, byte[] out) {
		if (!bInitialized) {
			setEncryption(null, 0, null);
		}
		int j = 0, k = 0;
		int[] s = new int[4];
		int iDitherR = 0xa55a;
		int iDitherL = 0x55aa;
		int iG = 0;
		for (int i = 0; i < in_len; ++i) {
			s[j] = decodeInputChar(in[i]);
			if (s[j] != 255) {
				++j;
				if (j == 4) {
					if (s[1] != 64) {
						out[k + 0] = (byte) (((s[0] & 255) << 2) | ((s[1] & 0x30) >> 4));
						if (s[2] != 64) {
							out[k + 1] = (byte) (((s[1] & 0x0F) << 4) | ((s[2] & 0x3C) >> 2));
							if (s[3] != 64) {
								out[k + 2] = (byte) (((s[2] & 0x03) << 6) | (s[3]));
								k += 3;
							} else {
								k += 2;
							}
						} else {
							k += 1;
						}
					}
					j = 0;
				}
			}
		}
		if (j >= 2) {
			out[k] = (byte) (((s[0] & 255) << 2) | ((s[1] & 0x30) >> 4));
			++k;
		}
		if (j == 3) {
			out[k] = (byte) (((s[1] & 0x0F) << 4) | ((s[2] & 0x3C) >> 2));
			++k;
		}
// Unglueing
		if (bToGlue) {
			for (int i = 0; i < k; ++i) {
				iG = out[i] & 0xff;
				out[i] = (byte) ((out[i] ^ iDitherL & 0xff) & 0xff);
				iDitherR = rotr16(iDitherR, 1) ^ iG;
				iDitherL = rotl16(iDitherL, 1) ^ iDitherR;
			}
		}
//.
		out[k] = '\0';
		return k;
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
		byte[] sBufferEn = new byte[256 * 4 / 3 + 1];
		int iSourceSize = 0;
		int iEncodedSize = 0;
		int iDecodedSize = 0;
		iSourceSize = sTest.length;
		int[] iCryptKey = new int[] { 128, 12345, 67890 };

		System.out.println("Plain text: " + new String(sTest));
		System.out.println(iSourceSize);
		System.out.println("-----------------------------------------------------------------------");
		System.out.println("Standard Base64 encoding");
		o.setEncryption(null, 0, S_ALPHABET_STANDARD);
		System.out.println("B64 code table: " + Arrays.toString(o.cAlphabet));
		System.out.println("B64 code index table: " + Arrays.toString(o.iAlphabetIndex));
		iEncodedSize = o.encrypt(sTest, sTest.length, sBufferEn, I_LENGTH_STANDARD, true);
		System.out.println("Standard Base64 encoded text:");
		System.out.println(new String(sBufferEn));
		System.out.println(iEncodedSize);
		iDecodedSize = o.decrypt(sBufferEn, iEncodedSize, sBufferDe);
		System.out.println("Standard Base64 decoded text:");
		System.out.println(new String(sBufferDe));
		System.out.println(iDecodedSize);
		System.out.println("-----------------------------------------------------------------------");
		sBufferDe = new byte[256];
		sBufferEn = new byte[256 * 4 / 3 + 1];
		System.out.println("Encryption with int[] as key: " + Arrays.toString(iCryptKey));
		o.setEncryption(iCryptKey, iCryptKey.length, S_ALPHABET_URL);
		System.out.println("B64 code table: " + Arrays.toString(o.cAlphabet));
		System.out.println("B64 code index table: " + Arrays.toString(o.iAlphabetIndex));
		iEncodedSize = o.encrypt(sTest, sTest.length, sBufferEn, I_LENGTH_PEM, false);
		System.out.println("Encrypted text:");
		System.out.println(new String(sBufferEn));
		System.out.println(iEncodedSize);
		iDecodedSize = o.decrypt(sBufferEn, iEncodedSize, sBufferDe);
		System.out.println("Decrypted text:");
		System.out.println(new String(sBufferDe));
		System.out.println(iDecodedSize);
		System.out.println("-----------------------------------------------------------------------");
		sBufferDe = new byte[256];
		sBufferEn = new byte[256 * 4 / 3 + 1];
		System.out.println("Encryption with String as key: " + "ThisIsTheKey1");
		o.setEncryption("ThisIsTheKey1", S_ALPHABET_QWERTY);
		System.out.println("B64 code table: " + Arrays.toString(o.cAlphabet));
		System.out.println("B64 code index table: " + Arrays.toString(o.iAlphabetIndex));
		iEncodedSize = o.encrypt(sTest, sTest.length, sBufferEn, I_LENGTH_MIME, false);
		System.out.println("Encrypted text:");
		System.out.println(new String(sBufferEn));
		System.out.println(iEncodedSize);
		iDecodedSize = o.decrypt(sBufferEn, iEncodedSize, sBufferDe);
		System.out.println("Decrypted text:");
		System.out.println(new String(sBufferDe));
		System.out.println(iDecodedSize);
		System.out.println("-----------------------------------------------------------------------");
		sBufferDe = new byte[256];
		sBufferEn = new byte[256 * 4 / 3 + 1];
		System.out.println("Encryption with int[0] as key: " + iCryptKey[0]);
		o.setEncryption(iCryptKey, 1, S_ALPHABET_STANDARD);
		System.out.println("B64 code table: " + Arrays.toString(o.cAlphabet));
		System.out.println("B64 code index table: " + Arrays.toString(o.iAlphabetIndex));
		iEncodedSize = o.encrypt(sTest, sTest.length, sBufferEn, 80, true);
		System.out.println("Encrypted text:");
		System.out.println(new String(sBufferEn));
		System.out.println(iEncodedSize);
		iDecodedSize = o.decrypt(sBufferEn, iEncodedSize, sBufferDe);
		System.out.println("Decrypted text:");
		System.out.println(new String(sBufferDe));
		System.out.println(iDecodedSize);
		System.out.println("-----------------------------------------------------------------------");

		sBufferDe = new byte[256];
		sBufferEn = new byte[256 * 4 / 3 + 1];
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
			iEncodedSize = o.encrypt(sBufferDe, iMsgSize, sBufferEn, I_LENGTH_STANDARD, (iCryptKey[2] & 1) == 1);
			iDecodedSize = o.decrypt(sBufferEn, iEncodedSize, sBufferDe);
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
