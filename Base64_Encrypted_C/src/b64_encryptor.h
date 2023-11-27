/*
 ============================================================================
 Name        : b64_encryptor.h
 Author      : Tofig Kareemov
 Version     :
 Copyright   : Your copyright notice
 Description : Base64 Encryptor in C, All in one H-file
 ============================================================================
 */

#ifndef B64_ENCRYPTOR_H_
#define B64_ENCRYPTOR_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <stdint.h>   // for uint32_t
#include <limits.h>   // for CHAR_BIT

//static void b64_init(unsigned int iKey);
//
//static unsigned int b64e_size(unsigned int in_size);
//
//static unsigned int b64d_size(unsigned int in_size);
//
//static unsigned int b64_encode(const unsigned char* in, unsigned int in_len, unsigned char* out);
//
//static unsigned int b64_decode(const unsigned char* in, unsigned int in_len, unsigned char* out);

static unsigned int currentTimeMillis() {
	struct timeval oTime;
	gettimeofday(&oTime, 0);
	long long iMilliseconds = oTime.tv_sec * 1000LL + oTime.tv_usec / 1000;
	return (unsigned int) iMilliseconds;
}

// Base64 char table - used internally for encoding
static unsigned char b64_code[65] = { 0 };
static unsigned char b64_index[65] = { 0 };

static int bInitialized = 0;
static int bToGlue = 0;

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
	return 64;
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
static void b64_shuffle(unsigned int iKey)
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
	bToGlue = 1;
}

/**************************************************************************/
static void b64_init(unsigned int iKey[], int iSize)
/**************************************************************************/
{
	unsigned char sB64Chars[] =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	bToGlue = 0;
	bInitialized = 0;
	for (int i = 0; i < 64; ++i) {
		b64_index[i] = (unsigned char) (i & 0xff);
		b64_code[i] = sB64Chars[i];
	}
	b64_code[64] = 0;
	for (int i = 0; i < iSize; ++i) {
		b64_shuffle(iKey[i]);
	}
	bInitialized = 1;
}

/**************************************************************************/
static void b64_init_string(char *sKey)
/**************************************************************************/
{
	unsigned char sB64Chars[] =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	bToGlue = 0;
	bInitialized = 0;
	for (int i = 0; i < 64; ++i) {
		b64_index[i] = (unsigned char) (i & 0xff);
		b64_code[i] = sB64Chars[i];
	}
	b64_code[64] = 0;
	if (sKey != 0) {
		for (int i = 0; i < strlen(sKey); ++i) {
			b64_shuffle(sKey[i]);
		}
	}
	bInitialized = 1;
}

/**************************************************************************/
static unsigned int b64e_size(unsigned int in_size)
/**************************************************************************/
{
	return ((in_size - 1) / 3) * 4 + 4;
}

/**************************************************************************/
static unsigned int b64d_size(unsigned int in_size)
/**************************************************************************/
{
	return ((3 * in_size) / 4);
}

/**************************************************************************/
static unsigned int b64_encode(const unsigned char *in, unsigned int in_len,
		unsigned char *out)
/**************************************************************************/
{
	if (!bInitialized) {
		b64_init(0, 0);
	}
	unsigned int i = 0, j = 0, k = 0, s[3];
	unsigned int iDither = 0xa55a;
	unsigned char iG = 0;

	for (i = 0; i < in_len; i++) {
		if (bToGlue) {
			iG = (unsigned char) (*(in + i) ^ iDither);
			s[j] = iG;
			iDither = rotr16(iDither, 1) ^ iG;
		} else {
			s[j] = *(in + i);
		}
		++j;
		if (j == 3) {
			out[k + 0] = b64_code[(s[0] & 255) >> 2];
			out[k + 1] = b64_code[((s[0] & 0x03) << 4) | ((s[1] & 0xF0) >> 4)];
			out[k + 2] = b64_code[((s[1] & 0x0F) << 2) | ((s[2] & 0xC0) >> 6)];
			out[k + 3] = b64_code[s[2] & 0x3F];
			j = 0;
			k += 4;
		}
	}
	if (j) {
		if (j == 1)
			s[1] = 0;
		out[k + 0] = b64_code[(s[0] & 255) >> 2];
		out[k + 1] = b64_code[((s[0] & 0x03) << 4) | ((s[1] & 0xF0) >> 4)];
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
static unsigned int b64_decode(const unsigned char *in, unsigned int in_len,
		unsigned char *out)
/**************************************************************************/
{
	if (!bInitialized) {
		b64_init(0, 0);
	}
	unsigned int i = 0, j = 0, k = 0, s[4];
	unsigned int iDither = 0xa55a;
	unsigned char iG = 0;

	for (i = 0; i < in_len; i++) {
		s[j] = b64_int_from_index(*(in + i));
		++j;
		if (j == 4) {
			out[k + 0] = ((s[0] & 255) << 2) | ((s[1] & 0x30) >> 4);
			if (s[2] != 64) {
				out[k + 1] = ((s[1] & 0x0F) << 4) | ((s[2] & 0x3C) >> 2);
				if ((s[3] != 64)) {
					out[k + 2] = ((s[2] & 0x03) << 6) | (s[3]);
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
	if (bToGlue) {
		for (int i = 0; i < k; i++) {
			iG = out[i];
			out[i] = (unsigned char) (out[i] ^ iDither);
			iDither = rotr16(iDither, 1) ^ iG;
		}
	}
//.
	out[k] = '\0';
	return k;
}

#endif /* B64_ENCRYPTOR_H_ */
