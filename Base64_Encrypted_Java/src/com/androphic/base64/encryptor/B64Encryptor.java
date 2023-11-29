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
	private final char[] iB64Code = new char[65];
	private final int[] iB64Index = new int[65];
	private boolean bB64Initialized = false;
	private boolean bB64ToGlue = false;

	private int mb64_int(int ch) {
		if (ch == 61) {
			return 64;
		} else if (ch == 43) {
			return 62;
		} else if (ch == 47) {
			return 63;
		} else if ((ch > 47) && (ch < 58)) {
			return ch + 4;
		} else if ((ch > 64) && (ch < 91)) {
			return ch - 'A';
		} else if ((ch > 96) && (ch < 123)) {
			return (ch - 'a') + 26;
		}
		return 255;
	}

	private int mb64_rotl16(int n, int c) {
		n = n & 0xFFFF;
		c &= 15;
		return ((n << c) | (n >> (16 - c))) & 0xFFFF;
	}

	private int mb64_rotr16(int n, int c) {
		n = n & 0xFFFF;
		c &= 15;
		return ((n >> c) | (n << (16 - c))) & 0xFFFF;
	}

	private int mb64_int_from_index(int ch) {
		int iCh = mb64_int(ch);
		if (iCh == 255) {
			return 255;
		}
		if (ch == 61) {
			return 64;
		} else {
			return iB64Index[iCh];
		}
	}

	private void mb64_shuffle(int iKey) {
		int iDither = 0x5aa5;
		for (int i = 0; i < 64; ++i) {
			iKey = mb64_rotl16(iKey, 1);
			iDither = mb64_rotr16(iDither, 1);
			int iSwitchIndex = i + (iKey ^ iDither) % (64 - i);
			char iA = iB64Code[i];
			iB64Code[i] = iB64Code[iSwitchIndex];
			iB64Code[iSwitchIndex] = iA;
		}
	}

	private void mb64_init_tables() {
		char[] sB64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
		for (int i = 0; i < 64; ++i) {
			iB64Index[i] = i & 0xff;
			iB64Code[i] = sB64Chars[i];
		}
		iB64Code[64] = 0;
	}

	private void mb64_index_tables() {
		for (int i = 0; i < 64; ++i) {
			iB64Index[mb64_int(iB64Code[i])] = i;
		}
	}

	public void b64_set_key_i(int[] iKey, int iSize) {
		mb64_init_tables();
		if (iKey != null) {
			for (int i = 0; i < iSize; ++i) {
				mb64_shuffle(iKey[i]);
			}
			mb64_index_tables();
			bB64ToGlue = true;
		}
		bB64Initialized = true;
	}

	public void b64_set_key_s(String sKey) {
		mb64_init_tables();
		if (sKey != null) {
			for (int i = 0; i < sKey.length(); ++i) {
				mb64_shuffle(0 | sKey.charAt(i) | (sKey.charAt(i) << 8));
			}
			mb64_index_tables();
			bB64ToGlue = true;
		}
		bB64Initialized = true;
	}

	public int b64_enc_size(int in_size) {
		return ((in_size - 1) / 3) * 4 + 4;
	}

	public int b64_dec_size(int in_size) {
		return ((3 * in_size) / 4);
	}

	public int b64_encode(byte[] in, int in_len, byte[] out, int iTextLineLength) {
		if (!bB64Initialized) {
			b64_set_key_i(null, 0);
		}
		int i = 0, j = 0, k = 0;
		int[] s = new int[3];
		int iDitherR = 0xa55a;
		int iDitherL = 0x55aa;
		int iG = 0;
		int iTextLineCount = 0;
		iTextLineLength = (iTextLineLength / 4) * 4;
		for (i = 0; i < in_len; i++) {
			if (bB64ToGlue) {
				iG = ((in[i] ^ iDitherL & 0xff) & 0xff);
				s[j] = iG;
				iDitherR = mb64_rotr16(iDitherR, 1) ^ iG;
				iDitherL = mb64_rotl16(iDitherL, 1) ^ iDitherR;
			} else {
				s[j] = (byte) (in[i]);
			}
			++j;
			if (j == 3) {
				out[k + 0] = (byte) iB64Code[(s[0] & 255) >> 2];
				out[k + 1] = (byte) iB64Code[((s[0] & 0x03) << 4) | ((s[1] & 0xF0) >> 4)];
				out[k + 2] = (byte) iB64Code[((s[1] & 0x0F) << 2) | ((s[2] & 0xC0) >> 6)];
				out[k + 3] = (byte) iB64Code[s[2] & 0x3F];
				j = 0;
				k += 4;
				if (iTextLineLength > 0) {
					iTextLineCount += 4;
					if (iTextLineCount >= iTextLineLength) {
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
			out[k + 0] = (byte) iB64Code[(s[0] & 255) >> 2];
			out[k + 1] = (byte) iB64Code[((s[0] & 0x03) << 4) | ((s[1] & 0xF0) >> 4)];
			if (j == 2) {
				out[k + 2] = (byte) iB64Code[((s[1] & 0x0F) << 2)];
			} else {
				out[k + 2] = '=';
			}
			out[k + 3] = '=';
			k += 4;
			if (iTextLineLength > 0) {
				iTextLineCount += 4;
				if (iTextLineCount >= iTextLineLength) {
					out[k] = '\n';
					++k;
					iTextLineCount = 0;
				}
			}
		}
		out[k] = '\0';
		return k;
	}

	public int b64_decode(byte[] in, int in_len, byte[] out) {
		if (!bB64Initialized) {
			b64_set_key_i(null, 0);
		}
		int j = 0, k = 0;
		int[] s = new int[4];
		int iDitherR = 0xa55a;
		int iDitherL = 0x55aa;
		int iG = 0;
		for (int i = 0; i < in_len; ++i) {
			s[j] = mb64_int_from_index(in[i]);
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
// Unglueing
		if (bB64ToGlue) {
			for (int i = 0; i < k; ++i) {
				iG = out[i] & 0xff;
				out[i] = (byte) ((out[i] ^ iDitherL & 0xff) & 0xff);
				iDitherR = mb64_rotr16(iDitherR, 1) ^ iG;
				iDitherL = mb64_rotl16(iDitherL, 1) ^ iDitherR;
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
			System.out.print(" " + o.mb64_rotl16(0xa5, i) + ", ");
		}
		System.out.println();
		for (int i = 0; i < 32; ++i) {
			System.out.print(" " + o.mb64_rotr16(0xa5, i) + ", ");
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
		int[] iCryptKey = new int[] { 128, 12345, 67890 }; // (int) System.currentTimeMillis();

		System.out.println("Plain text: " + new String(sTest));
		System.out.println(iSourceSize);
		System.out.println("-----------------------------------------------------------------------");
		System.out.println("Standard Base64 encoding");
		o.b64_set_key_i(null, 0);
		System.out.println("B64 code table: " + Arrays.toString(o.iB64Code));
		System.out.println("B64 code index table: " + Arrays.toString(o.iB64Index));
		iEncodedSize = o.b64_encode(sTest, sTest.length, sBufferEn, 16);
		System.out.println("Standard Base64 encoded text:");
		System.out.println(new String(sBufferEn));
		System.out.println(iEncodedSize);
		iDecodedSize = o.b64_decode(sBufferEn, iEncodedSize, sBufferDe);
		System.out.println("Standard Base64 decoded text:");
		System.out.println(new String(sBufferDe));
		System.out.println(iDecodedSize);
		System.out.println("-----------------------------------------------------------------------");
		sBufferDe = new byte[256];
		sBufferEn = new byte[256 * 4 / 3 + 1];
		System.out.println("Encryption with int[] as key");
		o.b64_set_key_i(iCryptKey, iCryptKey.length);
		System.out.println("B64 code table: " + Arrays.toString(o.iB64Code));
		System.out.println("B64 code index table: " + Arrays.toString(o.iB64Index));
		iEncodedSize = o.b64_encode(sTest, sTest.length, sBufferEn, 32);
		System.out.println("Encrypted text:");
		System.out.println(new String(sBufferEn));
		System.out.println(iEncodedSize);
		iDecodedSize = o.b64_decode(sBufferEn, iEncodedSize, sBufferDe);
		System.out.println("Decrypted text:");
		System.out.println(new String(sBufferDe));
		System.out.println(iDecodedSize);
		System.out.println("-----------------------------------------------------------------------");
		sBufferDe = new byte[256];
		sBufferEn = new byte[256 * 4 / 3 + 1];
		System.out.println("Encryption with String as key");
		o.b64_set_key_s("ThisIsTheKey1");
		System.out.println("B64 code table: " + Arrays.toString(o.iB64Code));
		System.out.println("B64 code index table: " + Arrays.toString(o.iB64Index));
		iEncodedSize = o.b64_encode(sTest, sTest.length, sBufferEn, 64);
		System.out.println("Encrypted text:");
		System.out.println(new String(sBufferEn));
		System.out.println(iEncodedSize);
		iDecodedSize = o.b64_decode(sBufferEn, iEncodedSize, sBufferDe);
		System.out.println("Decrypted text:");
		System.out.println(new String(sBufferDe));
		System.out.println(iDecodedSize);
		System.out.println("-----------------------------------------------------------------------");
		sBufferDe = new byte[256];
		sBufferEn = new byte[256 * 4 / 3 + 1];
		System.out.println("Encryption with int[0] as key");
		o.b64_set_key_i(iCryptKey, 1);
		System.out.println("B64 code table: " + Arrays.toString(o.iB64Code));
		System.out.println("B64 code index table: " + Arrays.toString(o.iB64Index));
		iEncodedSize = o.b64_encode(sTest, sTest.length, sBufferEn, 80);
		System.out.println("Encrypted text:");
		System.out.println(new String(sBufferEn));
		System.out.println(iEncodedSize);
		iDecodedSize = o.b64_decode(sBufferEn, iEncodedSize, sBufferDe);
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
			o.b64_set_key_i(iCryptKey, 3);
			for (int i1 = 0; i1 < iMsgSize; ++i1) {
				sBufferDe[i1] = (byte) (i1 + i);
			}
			iEncodedSize = o.b64_encode(sBufferDe, iMsgSize, sBufferEn, 0);
			iDecodedSize = o.b64_decode(sBufferEn, iEncodedSize, sBufferDe);
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
