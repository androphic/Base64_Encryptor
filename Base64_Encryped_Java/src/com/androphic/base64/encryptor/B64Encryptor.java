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
	private static final char[] b64_code = new char[65];
	private static final int[] b64_index = new int[65];
	private static boolean bInitialized = false;

	private static int b64_int(int ch) {
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
		return -1;
	}

	private static int rotl16(int n, int c) {
		n = n & 0xFFFF;
		c &= 15;
		return ((n << c) | (n >> (16 - c))) & 0xFFFF;
	}

	private static int rotr16(int n, int c) {
		n = n & 0xFFFF;
		c &= 15;
		return ((n >> c) | (n << (16 - c))) & 0xFFFF;
	}

	private static int b64_int_from_index(int ch) {
		if (ch == 61) {
			return 64;
		} else {
			return b64_index[b64_int(ch)];
		}
	}

	private static void b64_shuffle(int iKey) {
		int iDither = 0x5aa5;
		for (int i = 0; i < 64; ++i) {
			iKey = rotl16(iKey, 1);
			iDither = rotr16(iDither, 1);
			int iSwitchIndex = i + (iKey ^ iDither) % (64 - i);
			char iA = b64_code[i];
			b64_code[i] = b64_code[iSwitchIndex];
			b64_code[iSwitchIndex] = iA;
		}
		for (int i = 0; i < 64; ++i) {
			b64_index[b64_int(b64_code[i])] = i;
		}
	}

	private static void b64_init(int iKey) {
		char[] sB64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
		for (int i = 0; i < 64; ++i) {
			b64_index[i] = i & 0xff;
			b64_code[i] = sB64Chars[i];
		}
		b64_code[64] = 0;
		b64_shuffle(iKey);
		bInitialized = true;
	}

	private static int b64e_size(int in_size) {
		return ((in_size - 1) / 3) * 4 + 4;
	}

	private static int b64d_size(int in_size) {
		return ((3 * in_size) / 4);
	}

	private static int b64_encode(byte[] in, int in_len, byte[] out) {
		if (!bInitialized) {
			b64_init(0);
		}
		int i = 0, j = 0, k = 0;
		int[] s = new int[3];
		int iDither = 0xa55a;
		int iG = 0;
		for (i = 0; i < in_len; i++) {
// No gluieng
//			s[j] = (byte) (in[i]);
//			++j;
// Glueing
			iG = ((in[i] ^ iDither & 0xff) & 0xff);
			s[j] = iG;
			++j;
			iDither = rotr16(iDither, 1) ^ iG;
// .
			if (j == 3) {
				out[k + 0] = (byte) b64_code[(s[0] & 255) >> 2];
				out[k + 1] = (byte) b64_code[((s[0] & 0x03) << 4) + ((s[1] & 0xF0) >> 4)];
				out[k + 2] = (byte) b64_code[((s[1] & 0x0F) << 2) + ((s[2] & 0xC0) >> 6)];
				out[k + 3] = (byte) b64_code[s[2] & 0x3F];
				j = 0;
				k += 4;
			}
		}
		if (j != 0) {
			if (j == 1) {
				s[1] = 0;
			}
			out[k + 0] = (byte) b64_code[(s[0] & 255) >> 2];
			out[k + 1] = (byte) b64_code[((s[0] & 0x03) << 4) + ((s[1] & 0xF0) >> 4)];
			if (j == 2) {
				out[k + 2] = (byte) b64_code[((s[1] & 0x0F) << 2)];
			} else {
				out[k + 2] = '=';
			}
			out[k + 3] = '=';
			k += 4;
		}
		out[k] = '\0';
		return k;
	}

	private static int b64_decode(byte[] in, int in_len, byte[] out) {
		if (!bInitialized) {
			b64_init(0);
		}
		int j = 0, k = 0;
		int[] s = new int[4];
		int iDither = 0xa55a;
		int iG = 0;
		for (int i = 0; i < in_len; ++i) {
			s[j++] = b64_int_from_index(in[i]);
			if (j == 4) {
				if (s[1] != 64) {
					out[k + 0] = (byte) (((s[0] & 255) << 2) + ((s[1] & 0x30) >> 4));
					if (s[2] != 64) {
						out[k + 1] = (byte) (((s[1] & 0x0F) << 4) + ((s[2] & 0x3C) >> 2));
						if (s[3] != 64) {
							out[k + 2] = (byte) (((s[2] & 0x03) << 6) + (s[3]));
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
// Unglueing
		for (int i = 0; i < k; ++i) {
			iG = out[i] & 0xff;
			out[i] = (byte) ((out[i] ^ iDither & 0xff) & 0xff);
			iDither = rotr16(iDither, 1) ^ iG;
		}
//.
		out[k] = '\0';
		return k;
	}

	public static void main(String[] args) {
		System.out.println("B64 encryptor demonstration");
		int iCryptKey = 128; // (int) System.currentTimeMillis();
		b64_init(iCryptKey);
		System.out.println("Crypt key: 0x" + Integer.toHexString(iCryptKey));
		System.out.println("B64 code table: " + Arrays.toString(b64_code));
		byte[] sTest = "000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov."
				.getBytes();
		byte[] sBufferDe = new byte[256];
		byte[] sBufferEn = new byte[256 * 4 / 3];
		int iSourceSize = 0;
		int iEncodedSize = 0;
		int iDecodedSize = 0;
		iSourceSize = sTest.length;
		System.out.println("Plain text: " + new String(sTest));
		System.out.println(iSourceSize);
		iEncodedSize = b64_encode(sTest, sTest.length, sBufferEn);
		System.out.println("Crypt text: " + new String(sBufferEn));
		System.out.println(iEncodedSize);
		iDecodedSize = b64_decode(sBufferEn, iEncodedSize, sBufferDe);
		System.out.println("Decrypt text: " + new String(sBufferDe));
		System.out.println(iDecodedSize);
		int iTS = (int) System.currentTimeMillis();
		long iExperiments = 1234567;
		int iProgressPrev = 0;
		int iProgress = 0;
		int iMsgSize = 80;
		for (long i = 0; i < iExperiments; ++i) {
			iMsgSize = (int) (i % 256);
			iCryptKey = (int) System.currentTimeMillis();
			b64_init(iCryptKey);
			for (int i1 = 0; i1 < iMsgSize; ++i1) {
				sBufferDe[i1] = (byte) (i1 + i);
			}
			iEncodedSize = b64_encode(sBufferDe, iMsgSize, sBufferEn);
			iDecodedSize = b64_decode(sBufferEn, iEncodedSize, sBufferDe);
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
