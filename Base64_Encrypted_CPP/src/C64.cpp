//============================================================================
// Name        : C64.cpp
// Author      : Tofig Kareemov
// Version     :
// Copyright   : Your copyright notice
// Description : C++ implementation of Base64 Encryptor
//============================================================================

#include "C64.h"

const std::string C64::S_ALPHABET_STANDARD =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const std::string C64::S_ALPHABET_URL =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
const std::string C64::S_ALPHABET_QWERTY =
		"QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890-_=";
const std::string C64::S_ALPHABET_IMAP =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,=";
const std::string C64::S_ALPHABET_HQX =
		"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr=";
const std::string C64::S_ALPHABET_CRYPT =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=";
const std::string C64::S_ALPHABET_GEDCOM =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=";
const std::string C64::S_ALPHABET_BCRYPT =
		"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=";
const std::string C64::S_ALPHABET_XX =
		"+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=";
const std::string C64::S_ALPHABET_BASH =
		"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@_=";

const int C64::I_LINE_STANDARD = 0;
const int C64::I_LINE_MIME = 76;
const int C64::I_LINE_PEM = 64;

int C64::rotl16(int n, int c) {
	n = n & 0xFFFF;
	c &= 15;
	return ((n << c) | (n >> (16 - c))) & 0xFFFF;
}

int C64::rotr16(int n, int c) {
	n = n & 0xFFFF;
	c &= 15;
	return ((n >> c) | (n << (16 - c))) & 0xFFFF;
}

void C64::shuffleCodeTable(int iKey) {
	int iDitherForKey = 0x5aa5;
	for (int i = 0; i < 64; ++i) {
		iKey = rotl16(iKey, 1);
		iDitherForKey = rotr16(iDitherForKey, 1);
		int iSwitchIndex = i + (iKey ^ iDitherForKey) % (64 - i);
		char c = cAlphabet[i];
		cAlphabet[i] = cAlphabet[iSwitchIndex];
		cAlphabet[iSwitchIndex] = c;
	}
}

void C64::setAlphabet(const std::string &sAlphabet) {
	std::memset(cAlphabet, 0, sizeof(cAlphabet));
	std::memset(iAlphabetIndex, 0, sizeof(iAlphabetIndex));
	if (sAlphabet.empty() || sAlphabet.length() != 65) {
		std::memcpy(cAlphabet, S_ALPHABET_STANDARD.c_str(), 65);
		return;
	}
	std::memcpy(cAlphabet, sAlphabet.c_str(), 65);
	for (int i = 0; i < 65; ++i) {
		cAlphabet[i] = static_cast<char>(cAlphabet[i] & 0x7f);
		if (iAlphabetIndex[static_cast<int>(cAlphabet[i])] == 0) {
			iAlphabetIndex[static_cast<int>(cAlphabet[i])] = 1;
		} else {
			std::memcpy(cAlphabet, S_ALPHABET_STANDARD.c_str(), 65);
			return;
		}
	}
}

void C64::initTables(const std::string &sAlphabet) {
	bToGlue = false;
	bInitialized = false;
	resetStates();
	setAlphabet(sAlphabet);
}

void C64::indexTables() {
	std::memset(iAlphabetIndex, 0, sizeof(iAlphabetIndex));
	for (int i = 0; i < 128; ++i) {
		iAlphabetIndex[i] = 255;
	}
	for (int i = 0; i < 65; ++i) {
		iAlphabetIndex[static_cast<int>(cAlphabet[i])] = i;
	}
}

void C64::setEncryption(int iKey[], int iKeyLength,
		const std::string &sAlphabet) {
	initTables(sAlphabet);
	if (iKey != nullptr) {
		for (int i = 0; i < iKeyLength; ++i) {
			shuffleCodeTable(iKey[i]);
		}
		bToGlue = true;
	}
	indexTables();
	bInitialized = true;
}

void C64::setEncryption(const std::string &sKey, const std::string &sAlphabet) {
	initTables(sAlphabet);
	if (!sKey.empty()) {
		int iSize = sKey.length();
		for (int i = 0; i < iSize; ++i) {
			int c = sKey[i];
			shuffleCodeTable(0 | c | (c << 8));
		}
		bToGlue = true;
	}
	indexTables();
	bInitialized = true;
}

int C64::calcEncryptedLen(int iInputLen, int iLineLength, bool bPadding) {
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

int C64::calcDecryptedLen(int iInputSize, int iLineLength, bool bPadding) {
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
		// Handle padding
	}
	return iOutputLen;
}

void C64::resetStates() {
	oEncState.init();
	oDecState.init();
}

int C64::encrypt(const char *iIn, int iInLen, char *iOut, int iLineMaxLen,
		bool bPadding) {
	if (!bInitialized) {
		setEncryption(nullptr, 0, "");
	}
	iLineMaxLen = (iLineMaxLen / 4) * 4;
	State &o = oEncState;
	int k = 0;
	for (int i = 0; i < iInLen; i++) {
		if (bToGlue) {
			o.iG = ((iIn[i] ^ (o.iDL & 0xff)) & 0xff);
			o.iBuf[o.iB] = o.iG;
			o.iDR = rotr16(o.iDR, 1) ^ o.iG;
			o.iDL = rotl16(o.iDL, 1) ^ o.iDR;
		} else {
			o.iBuf[o.iB] = static_cast<int>(iIn[i]);
		}
		++o.iB;
		if (o.iB == 3) {
			iOut[k + 0] = cAlphabet[(o.iBuf[0] & 255) >> 2];
			iOut[k + 1] = cAlphabet[((o.iBuf[0] & 0x03) << 4)
					| ((o.iBuf[1] & 0xF0) >> 4)];
			iOut[k + 2] = cAlphabet[((o.iBuf[1] & 0x0F) << 2)
					| ((o.iBuf[2] & 0xC0) >> 6)];
			iOut[k + 3] = cAlphabet[o.iBuf[2] & 0x3F];
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
		iOut[k + 0] = cAlphabet[(o.iBuf[0] & 255) >> 2];
		iOut[k + 1] = cAlphabet[((o.iBuf[0] & 0x03) << 4)
				| ((o.iBuf[1] & 0xF0) >> 4)];
		k += 2;
		o.iLineLen += 2;
		if (o.iB == 2) {
			iOut[k] = cAlphabet[((o.iBuf[1] & 0x0F) << 2)];
			++k;
			++o.iLineLen;
		} else {
			if (bPadding) {
				iOut[k] = cAlphabet[64];
				++k;
				++o.iLineLen;
			}
		}
		if (bPadding) {
			iOut[k] = cAlphabet[64];
			++k;
			++o.iLineLen;
		}
	}
	iOut[k] = '\0';
	return k;
}

int C64::decrypt(const char *in, int in_len, char *out) {
	State &o = oDecState;
	if (!bInitialized) {
		setEncryption(nullptr, 0, "");
	}
	int k = 0;
	for (int i = 0; i < in_len; ++i) {
		o.iBuf[o.iB] = iAlphabetIndex[static_cast<int>(in[i])];
		if (o.iBuf[o.iB] != 255) {
			++o.iB;
			if (o.iB == 4) {
				if (o.iBuf[0] != 64) {
					if (o.iBuf[1] != 64) {
						out[k + 0] = static_cast<char>(((o.iBuf[0] & 255) << 2)
								| ((o.iBuf[1] & 0x30) >> 4));
						if (o.iBuf[2] != 64) {
							out[k + 1] = static_cast<char>(((o.iBuf[1] & 0x0F)
									<< 4) | ((o.iBuf[2] & 0x3C) >> 2));
							if (o.iBuf[3] != 64) {
								out[k + 2] = static_cast<char>(((o.iBuf[2]
										& 0x03) << 6) | (o.iBuf[3]));
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
		out[k] = static_cast<char>(((o.iBuf[0] & 255) << 2)
				| ((o.iBuf[1] & 0x30) >> 4));
		++k;
	}
	if (o.iB == 3) {
		out[k] = static_cast<char>(((o.iBuf[1] & 0x0F) << 4)
				| ((o.iBuf[2] & 0x3C) >> 2));
		++k;
	}
	if (bToGlue) {
		for (int i = 0; i < k; ++i) {
			o.iG = static_cast<int>(out[i]) & 0xff;
			out[i] = static_cast<char>((out[i] ^ (o.iDL & 0xff)) & 0xff);
			o.iDR = rotr16(o.iDR, 1) ^ o.iG;
			o.iDL = rotl16(o.iDL, 1) ^ o.iDR;
		}
	}
	out[k] = '\0';
	return k;
}

