//============================================================================
// Name        : test_C64.cpp
// Author      : Tofig Kareemov
// Version     :
// Copyright   : Your copyright notice
// Description : C++ implementation of Base64 Encryptor
//============================================================================

#include "C64.h"
#include <sys/time.h>

static unsigned int currentTimeMillis()
{
	struct timeval oTime;
	gettimeofday(&oTime, 0);
	long long iMilliseconds = oTime.tv_sec * 1000LL + oTime.tv_usec / 1000;
	return (unsigned int) iMilliseconds;
}

int main() {
	C64 o;
	std::cout << "B64 encryptor demonstration" << std::endl;
	std::cout
			<< "-----------------------------------------------------------------------"
			<< std::endl;

	const char *sTest =
			"000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.";
	int iSourceSize = std::strlen(sTest);
	int iEncodedLen = 0;
	int iDecodedLen = 0;

	std::cout << "Plain text: " << sTest << std::endl;
	std::cout << iSourceSize << std::endl;
	std::cout
			<< "-----------------------------------------------------------------------"
			<< std::endl;
	char sBufferEn[256 * 2];
	char sBufferDe[256];

	// Standard Base64 encoding
	o.setEncryption(nullptr, 0, C64::S_ALPHABET_STANDARD);
	std::cout << "B64 code table: " << o.cAlphabet << std::endl;
	iEncodedLen = o.encrypt(reinterpret_cast<const char*>(sTest), iSourceSize,
			reinterpret_cast<char*>(sBufferEn), 17, true);
	std::cout << "Standard Base64 encoded text:" << std::endl;
	std::cout << sBufferEn << std::endl;
	std::cout << iEncodedLen << std::endl;
	iDecodedLen = o.decrypt(reinterpret_cast<char*>(sBufferEn), iEncodedLen,
			reinterpret_cast<char*>(sBufferDe));
	std::cout << "Standard Base64 decoded text:" << std::endl;
	std::cout << sBufferDe << std::endl;
	std::cout << iDecodedLen << std::endl;
	std::cout
			<< "-----------------------------------------------------------------------"
			<< std::endl;

	// Encryption with int[] as key
	int iCryptKey[] = { 128, 12345, 67890 };
	std::cout << "Encryption with int[] as key: " << iCryptKey[0] << " "
			<< iCryptKey[1] << " " << iCryptKey[2] << std::endl;
	o.setEncryption(iCryptKey, sizeof(iCryptKey) / sizeof(iCryptKey[0]),
			C64::S_ALPHABET_URL);
	std::cout << "B64 code table: " << o.cAlphabet << std::endl;
	iEncodedLen = o.encrypt(reinterpret_cast<const char*>(sTest), iSourceSize,
			reinterpret_cast<char*>(sBufferEn), C64::I_LINE_PEM, false);
	std::cout << "Encrypted text:" << std::endl;
	std::cout << sBufferEn << std::endl;
	std::cout << iEncodedLen << std::endl;
	iDecodedLen = o.decrypt(reinterpret_cast<char*>(sBufferEn), iEncodedLen,
			reinterpret_cast<char*>(sBufferDe));
	std::cout << "Decrypted text:" << std::endl;
	std::cout << sBufferDe << std::endl;
	std::cout << iDecodedLen << std::endl;
	std::cout
			<< "-----------------------------------------------------------------------"
			<< std::endl;

	// Encryption with String as key
	o.setEncryption("ThisIsTheKey1", C64::S_ALPHABET_QWERTY);
	std::cout << "Encryption with String as key: " << "ThisIsTheKey1" << std::endl;
	std::cout << "B64 code table: " << o.cAlphabet << std::endl;
	iEncodedLen = o.encrypt(reinterpret_cast<const char*>(sTest), iSourceSize,
			reinterpret_cast<char*>(sBufferEn), C64::I_LINE_MIME, false);
	std::cout << "Encrypted text:" << std::endl;
	std::cout << sBufferEn << std::endl;
	std::cout << iEncodedLen << std::endl;
	iDecodedLen = o.decrypt(reinterpret_cast<char*>(sBufferEn), iEncodedLen,
			reinterpret_cast<char*>(sBufferDe));
	std::cout << "Decrypted text:" << std::endl;
	std::cout << sBufferDe << std::endl;
	std::cout << iDecodedLen << std::endl;
	std::cout
			<< "-----------------------------------------------------------------------"
			<< std::endl;

	// Encryption with int[0] as key
	o.setEncryption(&iCryptKey[0], 1, C64::S_ALPHABET_STANDARD);
	std::cout << "Encryption with int[0] as key: " << iCryptKey[0] << std::endl;
	std::cout << "B64 code table: " << o.cAlphabet << std::endl;
	iEncodedLen = o.encrypt(reinterpret_cast<const char*>(sTest), iSourceSize,
			reinterpret_cast<char*>(sBufferEn), 80, true);
	std::cout << "Encrypted text:" << std::endl;
	std::cout << sBufferEn << std::endl;
	std::cout << iEncodedLen << std::endl;
	iDecodedLen = o.decrypt(reinterpret_cast<char*>(sBufferEn), iEncodedLen,
			reinterpret_cast<char*>(sBufferDe));
	std::cout << "Decrypted text:" << std::endl;
	std::cout << sBufferDe << std::endl;
	std::cout << iDecodedLen << std::endl;
	std::cout
			<< "-----------------------------------------------------------------------"
			<< std::endl;

	char sBufferDe5[256];
	char sBufferEn5[256 * 2];
	int iTS = currentTimeMillis();
	long iExperiments = 1234567;
	int iProgressPrev = 0;
	int iProgress = 0;
	int iMsgSize = 80;
	for (long i = 0; i < iExperiments; ++i) {
		iMsgSize = static_cast<int>(i % 256);
		iCryptKey[0] = currentTimeMillis();
		iCryptKey[1] = currentTimeMillis();
		iCryptKey[2] = currentTimeMillis();
		o.setEncryption(iCryptKey, 3, C64::S_ALPHABET_QWERTY);
		o.resetStates();
		for (int i1 = 0; i1 < iMsgSize; ++i1) {
			sBufferDe5[i1] = static_cast<char>(i1 + i);
		}
		int iLineLength = iCryptKey[1] & 0x3f;
		bool bPadding = (iCryptKey[2] & 1) == 1;
		iEncodedLen = o.encrypt(reinterpret_cast<const char*>(sBufferDe5),
				iMsgSize, reinterpret_cast<char*>(sBufferEn5), iLineLength,
				bPadding);
		iDecodedLen = o.decrypt(reinterpret_cast<char*>(sBufferEn5),
				iEncodedLen, reinterpret_cast<char*>(sBufferDe5));
		int iCalc = o.calcEncryptedLen(iMsgSize, iLineLength, bPadding);
		if (iCalc != iEncodedLen) {
			std::cout << "ERR: Enc size calc is not correct, expected " << iCalc
					<< "( " << iMsgSize << ", " << iLineLength << ", "
					<< bPadding << ")" << ", real " << iEncodedLen << std::endl;
			return 1;
		}
		iCalc = o.calcDecryptedLen(iEncodedLen, iLineLength, bPadding);
		if (!(iCalc >= iDecodedLen && iCalc < iDecodedLen + 3)) {
			std::cout << "ERR: Dec size calc is not correct, expected " << iCalc
					<< "( " << iEncodedLen << ", " << iLineLength << ", "
					<< bPadding << ")" << ", real " << iDecodedLen << std::endl;
			return 1;
		}
		for (int i1 = 0; i1 < iMsgSize; ++i1) {
			if (sBufferDe5[i1] != static_cast<char>(i1 + i)) {
				std::cout << "ERR: " << i << ", " << sBufferEn5 << std::endl;
				return 1;
			}
		}
		iProgress = static_cast<int>(i * 100 / iExperiments);
		if (iProgressPrev != iProgress) {
			std::cout << "Progress: " << iProgress << "%, " << sBufferEn5
					<< std::endl;
			iProgressPrev = iProgress;
		}
	}
	std::cout << "Time (millis): "
			<< (currentTimeMillis() - iTS) << std::endl;

	return 0;
}
