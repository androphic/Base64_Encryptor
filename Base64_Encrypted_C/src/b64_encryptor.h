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

#include <string.h>

// Base64 char table - used internally for encoding
static unsigned char iB64Code[65] = { 0 };
static unsigned char iB64Index[65] = { 0 };

static int bB64Initialized = 0;
static int bB64ToGlue = 0;

/**************************************************************************/
static inline unsigned int mb64_int(unsigned int ch)
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
	return 255;
}

/**************************************************************************/
static inline unsigned int mb64_rotl16(unsigned int n, unsigned int c)
/**************************************************************************/
{
	n = n & 0xFFFF;
	c &= 15;
	return ((n << c) | (n >> (16 - c))) & 0xFFFF;
}

/**************************************************************************/
static inline unsigned int mb64_rotr16(unsigned int n, unsigned int c)
/**************************************************************************/
{
	n = n & 0xFFFF;
	c &= 15;
	return ((n >> c) | (n << (16 - c))) & 0xFFFF;
}

/**************************************************************************/
static inline unsigned int mb64_int_from_index(unsigned int ch)
/**************************************************************************/
{
	int iCh = mb64_int(ch);
	if (iCh == 255) {
		return 255;
	}
	if (ch == 61) {
		return 64;
	} else {
		return iB64Index[mb64_int(ch)];
	}
}

/**************************************************************************/
static inline void mb64_shuffle(unsigned int iKey)
/**************************************************************************/
{
	unsigned int iDither = 0x5aa5;
	for (int i = 0; i < 64; ++i) {
		iKey = mb64_rotl16(iKey, 1);
		iDither = mb64_rotr16(iDither, 1);
		int iSwitchIndex = i + (iKey ^ iDither) % (64 - i);
		unsigned char iA = iB64Code[i];
		iB64Code[i] = iB64Code[iSwitchIndex];
		iB64Code[iSwitchIndex] = iA;
	}
}

/**************************************************************************/
static void mb64_init_tables()
/**************************************************************************/
{
	unsigned char sB64Chars[] =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	bB64ToGlue = 0;
	bB64Initialized = 0;
	for (int i = 0; i < 64; ++i) {
		iB64Index[i] = (unsigned char) (i & 0xff);
		iB64Code[i] = sB64Chars[i];
	}
	iB64Code[64] = 0;
}

/**************************************************************************/
static void mb64_index_tables()
/**************************************************************************/
{
	for (int i = 0; i < 64; ++i) {
		iB64Index[mb64_int(iB64Code[i])] = i;
	}
}

/**************************************************************************/
static void b64_set_key_i(unsigned int iKey[], int iSize)
/**************************************************************************/
{
	mb64_init_tables();
	if (iKey != 0) {
		for (int i = 0; i < iSize; ++i) {
			mb64_shuffle(iKey[i]);
		}
		mb64_index_tables();
		bB64ToGlue = 1;
	}
	bB64Initialized = 1;
}

/**************************************************************************/
static void b64_set_key_s(char *sKey)
/**************************************************************************/
{
	mb64_init_tables();
	if (sKey != 0) {
		for (int i = 0; i < strlen(sKey); ++i) {
			mb64_shuffle(0 | sKey[i] | (sKey[i] << 8));
		}
		mb64_index_tables();
		bB64ToGlue = 1;
	}
	bB64Initialized = 1;
}

/**************************************************************************/
static unsigned int b64_encode(const unsigned char *in, unsigned int in_len,
		unsigned char *out, int iTextLineLength)
/**************************************************************************/
{
	if (!bB64Initialized) {
		b64_set_key_i(0, 0);
	}
	unsigned int i = 0, j = 0, k = 0, s[3];
	unsigned int iDitherR = 0xa55a;
	unsigned int iDitherL = 0x55aa;
	unsigned char iG = 0;
	int iTextLineCount = 0;

	iTextLineLength = (iTextLineLength / 4) * 4;
	for (i = 0; i < in_len; i++) {
		if (bB64ToGlue) {
			iG = (unsigned char) (*(in + i) ^ iDitherL);
			s[j] = iG;
			iDitherR = mb64_rotr16(iDitherR, 1) ^ iG;
			iDitherL = mb64_rotl16(iDitherL, 1) ^ iDitherR;
		} else {
			s[j] = *(in + i);
		}
		++j;
		if (j == 3) {
			out[k + 0] = iB64Code[(s[0] & 255) >> 2];
			out[k + 1] = iB64Code[((s[0] & 0x03) << 4) | ((s[1] & 0xF0) >> 4)];
			out[k + 2] = iB64Code[((s[1] & 0x0F) << 2) | ((s[2] & 0xC0) >> 6)];
			out[k + 3] = iB64Code[s[2] & 0x3F];
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
	if (j) {
		if (j == 1)
			s[1] = 0;
		out[k + 0] = iB64Code[(s[0] & 255) >> 2];
		out[k + 1] = iB64Code[((s[0] & 0x03) << 4) | ((s[1] & 0xF0) >> 4)];
		if (j == 2)
			out[k + 2] = iB64Code[((s[1] & 0x0F) << 2)];
		else
			out[k + 2] = '=';
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

/**************************************************************************/
static unsigned int b64_decode(const unsigned char *in, unsigned int in_len,
		unsigned char *out)
/**************************************************************************/
{
	if (!bB64Initialized) {
		b64_set_key_i(0, 0);
	}
	unsigned int i = 0, j = 0, k = 0, s[4];
	unsigned int iDitherR = 0xa55a;
	unsigned int iDitherL = 0x55aa;
	unsigned char iG = 0;

	for (i = 0; i < in_len; i++) {
		s[j] = mb64_int_from_index(*(in + i));
		if (s[j] != 255) { //processing only B64 symbols
			++j;
			if (j >= 4) {
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
	}
	if (bB64ToGlue) {
		for (int i = 0; i < k; i++) {
			iG = out[i];
			out[i] = (unsigned char) (out[i] ^ iDitherL);
			iDitherR = mb64_rotr16(iDitherR, 1) ^ iG;
			iDitherL = mb64_rotl16(iDitherL, 1) ^ iDitherR;
		}
	}
	out[k] = '\0';
	return k;
}

/**************************************************************************/
static inline unsigned int b64_enc_size(unsigned int iSize)
/**************************************************************************/
{
	return ((iSize - 1) / 3) * 4 + 4;
}

/**************************************************************************/
static inline unsigned int b64_dec_size(unsigned int iSize)
/**************************************************************************/
{
	return ((3 * iSize) / 4);
}

#endif /* B64_ENCRYPTOR_H_ */
