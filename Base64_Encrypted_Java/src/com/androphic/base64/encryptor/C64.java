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

public class C64 {
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

	public static final int I_LINE_STANDARD = 0;
	public static final int I_LINE_MIME = 76;
	public static final int I_LINE_PEM = 64;

	protected char[] cAlphabet = new char[65];
	protected final int[] iAlphabetIndex = new int[128];
	private boolean bInitialized = false;
	private boolean bToGlue = false;

	private class State {
		int[] iBuf = new int[4]; // Processing group buffer
		int iB = 0; // Processing group index
		int iDR = 0xa55a; // Dither rotating right
		int iDL = 0x55aa; // Dither rotating left
		int iG = 0; // Glue
		int iLineLen = 0; // Current text line length

		private void init() {
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

	protected int rotl16(int n, int c) {
		n = n & 0xFFFF;
		c &= 15;
		return ((n << c) | (n >> (16 - c))) & 0xFFFF;
	}

	protected int rotr16(int n, int c) {
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
			bToGlue = true;
		}
		indexTables();
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
		int k = 0;
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
				iOut[k + 0] = (byte) cAlphabet[(o.iBuf[0] & 255) >> 2];
				iOut[k + 1] = (byte) cAlphabet[((o.iBuf[0] & 0x03) << 4) | ((o.iBuf[1] & 0xF0) >> 4)];
				iOut[k + 2] = (byte) cAlphabet[((o.iBuf[1] & 0x0F) << 2) | ((o.iBuf[2] & 0xC0) >> 6)];
				iOut[k + 3] = (byte) cAlphabet[o.iBuf[2] & 0x3F];
				o.iB = 0;
				k += 4;
				o.iLineLen += 4;
				if (iLineMaxLen > 0) {
					if (o.iLineLen >= iLineMaxLen) {
						iOut[k] = '\r';
						++k;
						iOut[k] = '\n';
						++k;
						o.iLineLen = 0;
					}
				}
			}
		}
		if (o.iB != 0) {
			if (o.iB == 1) {
				o.iBuf[1] = 0;
			}
			iOut[k + 0] = (byte) cAlphabet[(o.iBuf[0] & 255) >> 2];
			iOut[k + 1] = (byte) cAlphabet[((o.iBuf[0] & 0x03) << 4) | ((o.iBuf[1] & 0xF0) >> 4)];
			k += 2;
			o.iLineLen += 2;
			if (o.iB == 2) {
				iOut[k] = (byte) cAlphabet[((o.iBuf[1] & 0x0F) << 2)];
				++k;
				++o.iLineLen;
			} else {
				if (bPadding) {
					iOut[k] = (byte) (cAlphabet[64] % 0xff);
					++k;
					++o.iLineLen;
				}
			}
			if (bPadding) {
				iOut[k] = (byte) (cAlphabet[64] % 0xff);
				++k;
				++o.iLineLen;
			}
		}
		iOut[k] = '\0';
		return k;
	}

	public int decrypt(byte[] in, int in_len, byte[] out) {
		State o = oDecState;
		if (!bInitialized) {
			setEncryption(null, 0, null);
		}
		int k = 0;
		for (int i = 0; i < in_len; ++i) {
			o.iBuf[o.iB] = iAlphabetIndex[in[i]];
			if (o.iBuf[o.iB] != 255) {
				++o.iB;
				if (o.iB == 4) {
					if (o.iBuf[0] != 64) {
						if (o.iBuf[1] != 64) {
							out[k + 0] = (byte) (((o.iBuf[0] & 255) << 2) | ((o.iBuf[1] & 0x30) >> 4));
							if (o.iBuf[2] != 64) {
								out[k + 1] = (byte) (((o.iBuf[1] & 0x0F) << 4) | ((o.iBuf[2] & 0x3C) >> 2));
								if (o.iBuf[3] != 64) {
									out[k + 2] = (byte) (((o.iBuf[2] & 0x03) << 6) | (o.iBuf[3]));
									k += 3;
								} else {
									k += 2;
								}
							} else {
								k += 1;
							}
						}
					}
					o.iB = 0;
				}
			}
		}
		if (o.iB >= 2) {
			out[k] = (byte) (((o.iBuf[0] & 255) << 2) | ((o.iBuf[1] & 0x30) >> 4));
			++k;
		}
		if (o.iB == 3) {
			out[k] = (byte) (((o.iBuf[1] & 0x0F) << 4) | ((o.iBuf[2] & 0x3C) >> 2));
			++k;
		}
		if (bToGlue) {
			for (int i = 0; i < k; ++i) {
				o.iG = out[i] & 0xff;
				out[i] = (byte) ((out[i] ^ o.iDL & 0xff) & 0xff);
				o.iDR = rotr16(o.iDR, 1) ^ o.iG;
				o.iDL = rotl16(o.iDL, 1) ^ o.iDR;
			}
		}
		out[k] = '\0';
		return k;
	}
}
