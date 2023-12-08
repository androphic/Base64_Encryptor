//============================================================================
// Name        : C64.h
// Author      : Tofig Kareemov
// Version     :
// Copyright   : Your copyright notice
// Description : C++ implementation of Base64 Encryptor
//============================================================================

#ifndef C64_H
#define C64_H

#include <iostream>
#include <cstring>

typedef unsigned char byte;

class C64 {
public:
	static const std::string S_ALPHABET_STANDARD;
	static const std::string S_ALPHABET_URL;
	static const std::string S_ALPHABET_QWERTY;
	static const std::string S_ALPHABET_IMAP;
	static const std::string S_ALPHABET_HQX;
	static const std::string S_ALPHABET_CRYPT;
	static const std::string S_ALPHABET_GEDCOM;
	static const std::string S_ALPHABET_BCRYPT;
	static const std::string S_ALPHABET_XX;
	static const std::string S_ALPHABET_BASH;

	static const int I_LINE_STANDARD;
	static const int I_LINE_MIME;
	static const int I_LINE_PEM;

	C64() {
		resetStates();
	}

	void setEncryption(int iKey[], int iKeyLength,
			const std::string &sAlphabet);
	void setEncryption(const std::string &sKey, const std::string &sAlphabet);

	int calcEncryptedLen(int iInputLen, int iLineLength, bool bPadding);
	int calcDecryptedLen(int iInputSize, int iLineLength, bool bPadding);

	void resetStates();

	int encrypt(const char *iIn, int iInLen, char *iOut, int iLineMaxLen,
			bool bPadding);
	int decrypt(const char *in, int in_len, char *out);
	char cAlphabet[66];

private:
	int iAlphabetIndex[129];
	bool bInitialized;
	bool bToGlue;

	struct State {
		int iBuf[4];
		int iB;
		int iDR;
		int iDL;
		int iG;
		int iLineLen;

		void init() {
			std::memset(iBuf, 0, sizeof(iBuf));
			iB = 0;
			iDR = 0xa55a;
			iDL = 0x55aa;
			iG = 0;
			iLineLen = 0;
		}
	};

	State oEncState;
	State oDecState;

	int rotl16(int n, int c);
	int rotr16(int n, int c);

	void shuffleCodeTable(int iKey);
	void setAlphabet(const std::string &sAlphabet);
	void initTables(const std::string &sAlphabet);
	void indexTables();
};


#endif // C64_H
