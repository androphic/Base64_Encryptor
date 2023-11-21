/*
 ============================================================================
 Name        : b64_encryptor.c
 Author      : Tofig Kareemov
 Version     :
 Copyright   : Your copyright notice
 Description : Base64 Encryptor in C, Ansi-style
 ============================================================================
 */

#include "b64_encryptor.h"

// Base64 char table - used internally for encoding
unsigned char b64_code[65] = { 0 };
unsigned char b64_index[65] = { 0 };

int bInitialized = 0;

/**************************************************************************/
static inline unsigned int b64_int(unsigned int ch)
/**************************************************************************/
{
// ASCII to base64_int
// 65-90  Upper Case  >>  0-25
// 97-122 Lower Case  >>  26-51
// 48-57  Numbers     >>  52-61
// 43     Plus (+)    >>  62
// 47     Slash (/)   >>  63
// 61     Equal (=)   >>  64~
//	unsigned int iReturn = 0;
//	if (ch == 61) {
//		return 64;
//	} else if (ch == 43) {
//		iReturn = 62;
//	} else if (ch == 47) {
//		iReturn = 63;
//	} else if ((ch > 47) && (ch < 58)) {
//		iReturn = ch + 4;
//	} else if ((ch > 64) && (ch < 91)) {
//		iReturn = ch - 'A';
//	} else if ((ch > 96) && (ch < 123)) {
//		iReturn = (ch - 'a') + 26;
//	}
//	return iReturn;

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

/**************************************************************************/
static inline unsigned int rotl16(unsigned int n, unsigned int c)
/**************************************************************************/
{
	n = n & 0xFFFF;
	c &= 15;
	return ((n << c) | (n >> (16 - c))) & 0xFFFF;
}

/**************************************************************************/
static inline unsigned int rotr16(unsigned int n, unsigned int c)
/**************************************************************************/
{
	n = n & 0xFFFF;
	c &= 15;
	return ((n >> c) | (n << (16 - c))) & 0xFFFF;
}

/**************************************************************************/
static inline unsigned int b64_int_from_index(unsigned int ch)
/**************************************************************************/
{
	if (ch == 61) {
		return 64;
	} else {
		return b64_index[b64_int(ch)];
	}
}

/**************************************************************************/
void b64_shuffle(unsigned int iKey)
/**************************************************************************/
{
	unsigned int iDither = 0x5aa5;
	for (int i = 0; i < 64; ++i) {
		iKey = rotl16(iKey, 1);
		iDither = rotr16(iDither, 1);
		int iSwitchIndex = i + (iKey ^ iDither) % (64 - i);
		unsigned char iA = b64_code[i];
		b64_code[i] = b64_code[iSwitchIndex];
		b64_code[iSwitchIndex] = iA;
	}
	for (int i = 0; i < 64; ++i) {
		b64_index[b64_int(b64_code[i])] = i;
	}
}

/**************************************************************************/
void b64_init(unsigned int iKey)
/**************************************************************************/
{
	unsigned char sB64Chars[] =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	for (int i = 0; i < 64; ++i) {
		b64_index[i] = (unsigned char) (i & 0xff);
		b64_code[i] = sB64Chars[i];
	}
	b64_code[64] = 0;
	b64_shuffle(iKey);
	bInitialized = 1;
}

/**************************************************************************/
unsigned int b64e_size(unsigned int in_size)
/**************************************************************************/
{
	return ((in_size - 1) / 3) * 4 + 4;
}

/**************************************************************************/
unsigned int b64d_size(unsigned int in_size)
/**************************************************************************/
{
	return ((3 * in_size) / 4);
}

/**************************************************************************/
unsigned int b64_encode(const unsigned char *in, unsigned int in_len,
		unsigned char *out)
/**************************************************************************/
{
	if (!bInitialized) {
		b64_init(0);
	}
	unsigned int i = 0, j = 0, k = 0, s[3];
	unsigned int iDither = 0xa55a;
	unsigned char iG = 0;

	for (i = 0; i < in_len; i++) {
// No glueing
//		s[j] = *(in + i);
//		++j;
// Glueing
		iG = (unsigned char) (*(in + i) ^ iDither);
		s[j] = iG;
		++j;
		iDither = rotr16(iDither, 1) ^ iG;
//.
		if (j == 3) {
			out[k + 0] = b64_code[(s[0] & 255) >> 2];
			out[k + 1] = b64_code[((s[0] & 0x03) << 4) + ((s[1] & 0xF0) >> 4)];
			out[k + 2] = b64_code[((s[1] & 0x0F) << 2) + ((s[2] & 0xC0) >> 6)];
			out[k + 3] = b64_code[s[2] & 0x3F];
			j = 0;
			k += 4;
		}
	}
	if (j) {
		if (j == 1)
			s[1] = 0;
		out[k + 0] = b64_code[(s[0] & 255) >> 2];
		out[k + 1] = b64_code[((s[0] & 0x03) << 4) + ((s[1] & 0xF0) >> 4)];
		if (j == 2)
			out[k + 2] = b64_code[((s[1] & 0x0F) << 2)];
		else
			out[k + 2] = '=';
		out[k + 3] = '=';
		k += 4;
	}
	out[k] = '\0';
	return k;
}

/**************************************************************************/
unsigned int b64_decode(const unsigned char *in, unsigned int in_len,
		unsigned char *out)
/**************************************************************************/
{
	if (!bInitialized) {
		b64_init(0);
	}
	unsigned int i = 0, j = 0, k = 0, s[4];
	unsigned int iDither = 0xa55a;
	unsigned char iG = 0;

	for (i = 0; i < in_len; i++) {
		s[j] = b64_int_from_index(*(in + i));
		++j;
		if (j == 4) {
			out[k + 0] = ((s[0] & 255) << 2) + ((s[1] & 0x30) >> 4);
			if (s[2] != 64) {
				out[k + 1] = ((s[1] & 0x0F) << 4) + ((s[2] & 0x3C) >> 2);
				if ((s[3] != 64)) {
					out[k + 2] = ((s[2] & 0x03) << 6) + (s[3]);
					k += 3;
				} else {
					k += 2;
				}
			} else {
				k += 1;
			}
			j = 0;
		}
	}

//Unglueing
	for (int i = 0; i < k; i++) {
		iG = out[i];
		out[i] = (unsigned char) (out[i] ^ iDither);
		iDither = rotr16(iDither, 1) ^ iG;
	}
//.
	out[k] = '\0';
	return k;
}

/**************************************************************************/
#define iColSize 1000
int main(void)
/**************************************************************************/
{

//	int iCol[iColSize * iColSize] = { 0 };
//	int iColIndex = 0;
//
//	for (int iSize = 10; iSize <= 12; iSize=iSize+1) {
//		for (int i = 1; i <= iSize; ++i) {
//			for (int i1 = 1; i1 <= i; ++i1) {
//				int iRes = i * i1;
//				int bFound = 0;
//				for (int i2 = 0; i2 < iColIndex; ++i2) {
//					if (iCol[i2] == iRes)
//						bFound = 1;
//				}
//				if (!bFound) {
//					iCol[iColIndex] = iRes;
//					++iColIndex;
//				}
//			}
//		}
//		printf("%d = %d\n", iSize, iColIndex);
//	}
//	for (int i2 = 0; i2 < iColSize * iColSize; ++i2) {
//		printf("%d ", iCol[i2]);
//	}
//	printf("\n");
//	printf("%d \n", iColIndex);

//	return 0;

	printf("B64 encryptor demonstration\n");
	unsigned int iCryptKey = 128; //currentTimeMillis();
	b64_init(iCryptKey);
	printf("Crypt key: 0x%x\n", iCryptKey);
	printf("B64 code table: %s\n", b64_code);

	const char sTest[256] =
			"000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.";
	//char *sTest = (char*) b64_code;
	unsigned char sBufferDe[256] = { 0 };
	unsigned char sBufferEn[256 * 4 / 3] = { 0 };
	int iSourceSize = 0;
	int iEncodedSize = 0;
	int iDecodedSize = 0;

	iSourceSize = strlen(sTest);
	printf("Plain text: %s\n", sTest);
	printf("%d\n", iSourceSize);

	iEncodedSize = b64_encode((unsigned char*) sTest, strlen(sTest),
			(unsigned char*) sBufferEn);
	printf("Crypt text: %s\n", sBufferEn);
	printf("%d\n", iEncodedSize);

	iDecodedSize = b64_decode((unsigned char*) sBufferEn, iEncodedSize,
			(unsigned char*) sBufferDe);
	printf("Decrypt text: %s\n", sBufferDe);
	printf("%d\n", iDecodedSize);

	int iTS = currentTimeMillis();
	long iExperiments = 1234567;
	int iProgressPrev = 0;
	int iProgress = 0;
	int iMsgSize = 80;
	for (long i = 0; i < iExperiments; ++i) {
		iMsgSize = i % 256;
		iCryptKey = currentTimeMillis();
		b64_init(iCryptKey);
		for (int i1 = 0; i1 < iMsgSize; ++i1) {
			sBufferDe[i1] = (unsigned char) (i1 + i);
		}
		iEncodedSize = b64_encode((unsigned char*) sBufferDe, iMsgSize,
				(unsigned char*) sBufferEn);
		iDecodedSize = b64_decode((unsigned char*) sBufferEn, iEncodedSize,
				(unsigned char*) sBufferDe);
		for (int i1 = 0; i1 < iMsgSize; ++i1) {
			if (sBufferDe[i1] != (unsigned char) (i1 + i)) {
				printf("ERR: %ld, %s\n", i, sBufferEn);
				goto END;
			}
		}
		iProgress = i * 100 / iExperiments;
		if (iProgressPrev != iProgress) {
			printf("Progress: %d%%, %s\n", iProgress, sBufferEn);
			iProgressPrev = iProgress;
		}
	}
	END: printf("Time (millis): %d\n", currentTimeMillis() - iTS);

	return 0;
}

