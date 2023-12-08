/*
 ============================================================================
 Name        : c64.h
 Author      : Tofig Kareemov
 Version     :
 Copyright   : Your copyright notice
 Description : Base64 Encryptor in C, All in one H-file
 ============================================================================
 */

#ifndef C64_H_
#define C64_H_

#include <string.h>
#include <stdio.h>

//TK: Be gentle with following alphabet strings!
static unsigned char S_ALPHABET_STANDARD[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
static unsigned char S_ALPHABET_URL[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
static unsigned char S_ALPHABET_QWERTY[] =
		"QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890-_=";
static unsigned char S_ALPHABET_IMAP[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,=";
static unsigned char S_ALPHABET_HQX[] =
		"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr=";
static unsigned char S_ALPHABET_CRYPT[] =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=";
static unsigned char S_ALPHABET_GEDCOM[] =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=";
static unsigned char S_ALPHABET_BCRYPT[] =
		"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=";
static unsigned char S_ALPHABET_XX[] =
		"+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=";
static unsigned char S_ALPHABET_BASH[] =
		"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@_=";
//.

static int I_LINE_STANDARD = 0;
static int I_LINE_MIME = 76;
static int I_LINE_PEM = 64;

static unsigned char cAlphabet[66] = { 0 };
static unsigned char iAlphabetIndex[129] = { 0 };
static int bInitialized = 0;
static int bToGlue = 0;

struct State {
	unsigned char iBuf[4];
	int iB;
	int iDR;
	int iDL;
	unsigned char iG;
	int iLineLen;
};

struct State oEncState;
struct State oDecState;

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
static inline void shuffleCodeTable(unsigned int iKey)
/**************************************************************************/
{
	unsigned int iDitherForKey = 0x5aa5;
	for (int i = 0; i < 64; ++i) {
		iKey = rotl16(iKey, 1);
		iDitherForKey = rotr16(iDitherForKey, 1);
		int iSwitchIndex = i + (iKey ^ iDitherForKey) % (64 - i);
		unsigned char c = cAlphabet[i];
		cAlphabet[i] = cAlphabet[iSwitchIndex];
		cAlphabet[iSwitchIndex] = c;
	}
}

/**************************************************************************/
static inline void setAlphabet(unsigned char *sNewAlphabet)
/**************************************************************************/
{
	if ((sNewAlphabet == 0) || (strlen((char*) sNewAlphabet) != 65)) {
		for (int i = 0; i < 65; ++i) {
			cAlphabet[i] = S_ALPHABET_STANDARD[i];
			return;
		}
	}
	for (int i = 0; i < 65; ++i) {
		cAlphabet[i] = sNewAlphabet[i];
	}
//	printf("zzz table: %s\n", (char*)cAlphabet);
	for (int i = 0; i < 128; ++i) {
		iAlphabetIndex[i] = 0;
	}
	for (int i = 0; i < 65; ++i) {
		if (iAlphabetIndex[cAlphabet[i]] == 0) {
			iAlphabetIndex[cAlphabet[i]] = 1;
		} else {
			for (int i = 0; i < 65; ++i) {
				cAlphabet[i] = S_ALPHABET_STANDARD[i];
				return;
			}
		}
	}
}

/**************************************************************************/
static inline void initState(struct State *oState)
/**************************************************************************/
{
	oState->iB = 0;
	oState->iBuf[0] = 0;
	oState->iBuf[1] = 0;
	oState->iBuf[2] = 0;
	oState->iBuf[3] = 0;
	oState->iDR = 0xa55a;
	oState->iDL = 0x55aa;
	oState->iG = 0;
	oState->iLineLen = 0;
}

/**************************************************************************/
static inline void resetStates()
/**************************************************************************/
{
	initState(&oEncState);
	initState(&oDecState);
}

/**************************************************************************/
static inline void initTables(unsigned char *sNewAlphabet)
/**************************************************************************/
{
	bToGlue = 0;
	bInitialized = 0;
	resetStates();
	setAlphabet(sNewAlphabet);
}

/**************************************************************************/
static inline void indexTables()
/**************************************************************************/
{
	for (int i = 0; i < 128; ++i) {
		iAlphabetIndex[i] = 255;
	}
	for (int i = 0; i < 65; ++i) {
		iAlphabetIndex[cAlphabet[i]] = i;
	}
}

/**************************************************************************/
static void setEncryption(unsigned int *iKey, int iKeyLength,
		unsigned char *sAlphabet)
/**************************************************************************/
{
	initTables(sAlphabet);
	if (iKey != 0 && iKeyLength > 0) {
		for (int i = 0; i < iKeyLength; ++i) {
			shuffleCodeTable(iKey[i]);
		}
		bToGlue = 1;
	}
	indexTables();
	bInitialized = 1;
}

/**************************************************************************/
static void setEncryptionAsString(unsigned char *sKey, unsigned char *sAlphabet)
/**************************************************************************/
{
	initTables(sAlphabet);
	if (sKey != 0 && strlen((char*) sKey) > 0) {
		for (int i = 0; i < strlen((char*) sKey); ++i) {
			shuffleCodeTable((0 | sKey[i] << 8) | sKey[i]);
		}
		bToGlue = 1;
	}
	indexTables();
	bInitialized = 1;
}

/**************************************************************************/
static int encrypt(unsigned char *iIn, int iInLen, unsigned char *iOut,
		int iLineMaxLen, int bPadding)
/**************************************************************************/
{
	struct State *o = &oEncState;
	if (!bInitialized) {
		setEncryption(0, 0, 0);
	}
	iLineMaxLen = (iLineMaxLen / 4) * 4;
	int k = 0;
	for (int i = 0; i < iInLen; i++) {
		if (bToGlue) {
			o->iG = iIn[i] ^ (unsigned char) o->iDL;
			o->iBuf[o->iB] = o->iG;
			o->iDR = rotr16(o->iDR, 1) ^ o->iG;
			o->iDL = rotl16(o->iDL, 1) ^ o->iDR;
		} else {
			o->iBuf[o->iB] = iIn[i];
		}
		++o->iB;
		if (o->iB == 3) {
			iOut[k + 0] = cAlphabet[(o->iBuf[0] & 255) >> 2];
			iOut[k + 1] = cAlphabet[((o->iBuf[0] & 0x03) << 4)
					| ((o->iBuf[1] & 0xF0) >> 4)];
			iOut[k + 2] = cAlphabet[((o->iBuf[1] & 0x0F) << 2)
					| ((o->iBuf[2] & 0xC0) >> 6)];
			iOut[k + 3] = cAlphabet[o->iBuf[2] & 0x3F];
			o->iB = 0;
			k += 4;
			o->iLineLen += 4;
			if (iLineMaxLen > 0) {
				if (o->iLineLen >= iLineMaxLen) {
					iOut[k] = '\r';
					++k;
					iOut[k] = '\n';
					++k;
					o->iLineLen = 0;
				}
			}
		}
	}
	if (o->iB != 0) {
		if (o->iB == 1) {
			o->iBuf[1] = 0;
		}
		iOut[k + 0] = cAlphabet[(o->iBuf[0] & 255) >> 2];
		iOut[k + 1] = cAlphabet[((o->iBuf[0] & 0x03) << 4)
				| ((o->iBuf[1] & 0xF0) >> 4)];
		k += 2;
		o->iLineLen += 2;
		if (o->iB == 2) {
			iOut[k] = cAlphabet[((o->iBuf[1] & 0x0F) << 2)];
			++k;
			++o->iLineLen;
		} else {
			if (bPadding) {
				iOut[k] = cAlphabet[64] % 0xff;
				++k;
				++o->iLineLen;
			}
		}
		if (bPadding) {
			iOut[k] = cAlphabet[64] % 0xff;
			++k;
			++o->iLineLen;
		}
	}
	iOut[k] = '\0';
	return k;
}

/**************************************************************************/
static int decrypt(unsigned char *in, int in_len, unsigned char *out)
/**************************************************************************/
{
	struct State *o = &oDecState;
	if (!bInitialized) {
		setEncryption(0, 0, 0);
	}
	int k = 0;
	for (int i = 0; i < in_len; ++i) {
		o->iBuf[o->iB] = iAlphabetIndex[in[i]];
		if (o->iBuf[o->iB] != 255) {
			++o->iB;
			if (o->iB == 4) {
				if (o->iBuf[0] != 64) {
					if (o->iBuf[1] != 64) {
						out[k + 0] = (((o->iBuf[0] & 255) << 2)
								| ((o->iBuf[1] & 0x30) >> 4));
						if (o->iBuf[2] != 64) {
							out[k + 1] = (((o->iBuf[1] & 0x0F) << 4)
									| ((o->iBuf[2] & 0x3C) >> 2));
							if (o->iBuf[3] != 64) {
								out[k + 2] = (((o->iBuf[2] & 0x03) << 6)
										| (o->iBuf[3]));
								k += 3;
							} else {
								k += 2;
							}
						} else {
							k += 1;
						}
					}
				}
				o->iB = 0;
			}
		}
	}
	if (o->iB >= 2) {
		out[k] = (((o->iBuf[0] & 255) << 2) | ((o->iBuf[1] & 0x30) >> 4));
		++k;
	}
	if (o->iB == 3) {
		out[k] = (((o->iBuf[1] & 0x0F) << 4) | ((o->iBuf[2] & 0x3C) >> 2));
		++k;
	}
	if (bToGlue) {
		for (int i = 0; i < k; ++i) {
			o->iG = out[i] & 0xff;
			out[i] = out[i] ^ (unsigned char) o->iDL;
			o->iDR = rotr16(o->iDR, 1) ^ o->iG;
			o->iDL = rotl16(o->iDL, 1) ^ o->iDR;
		}
	}
	out[k] = '\0';
	return k;
}

/**************************************************************************/
static inline int calcEncryptedLen(int iInputLen, int iLineLength, int bPadding)
/**************************************************************************/
{
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

/**************************************************************************/
static inline int calcDecryptedLen(int iInputSize, int iLineLength,
		int bPadding)
/**************************************************************************/
{
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

#endif /* C64_H_ */
