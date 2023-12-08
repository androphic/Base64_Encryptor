/*
 ============================================================================
 Name        : b64_encryptor.c
 Author      : Tofig Kareemov
 Version     :
 Copyright   : Your copyright notice
 Description : Base64 Encryptor in C
 ============================================================================
 */

#include <c64.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdint.h>
#include <limits.h>

/**************************************************************************/
static unsigned int currentTimeMillis()
/**************************************************************************/
{
	struct timeval oTime;
	gettimeofday(&oTime, 0);
	long long iMilliseconds = oTime.tv_sec * 1000LL + oTime.tv_usec / 1000;
	return (unsigned int) iMilliseconds;
}

/**************************************************************************/
int main(void)
/**************************************************************************/
{
	printf("B64 encryptor demonstration\n");
	unsigned int iCryptKey[] = { 128, 12345, 67890 };
	int iCryptKeySize = sizeof(iCryptKey) / sizeof(iCryptKey[0]);
	const char sTest[256] =
			"000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.";
	unsigned char sBufferDe[256] = { 0 };
	unsigned char sBufferEn[256 * 2] = { 0 };
	int iSourceSize = 0;
	int iEncodedSize = 0;
	int iDecodedSize = 0;

	iSourceSize = strlen(sTest);
	printf("Plain text: %s\n", sTest);
	printf("%d\n", iSourceSize);
	printf(
			"-----------------------------------------------------------------------\n");
	setEncryption(0, 0, S_ALPHABET_STANDARD);
	printf("B64 code table: %s\n", cAlphabet);
	iEncodedSize = encrypt((unsigned char*) sTest, strlen(sTest),
			(unsigned char*) sBufferEn, 17, 1);
	printf("Standard Base64 encoded text:\n");
	printf("%s\n", sBufferEn);
	printf("%d\n", iEncodedSize);
	iDecodedSize = decrypt((unsigned char*) sBufferEn, iEncodedSize,
			(unsigned char*) sBufferDe);
	printf("Standard Base64 decoded text: %s\n", sBufferDe);
	printf("%d\n", iDecodedSize);
	printf(
			"-----------------------------------------------------------------------\n");
	printf("Encryption with int[] as a key:");
	for (int i = 0; i < iCryptKeySize; ++i) {
		printf(" 0x%x", iCryptKey[i]);
	}
	printf("\n");
	setEncryption(iCryptKey, iCryptKeySize, S_ALPHABET_URL);
	printf("B64 code table: %s\n", cAlphabet);
	iEncodedSize = encrypt((unsigned char*) sTest, strlen(sTest),
			(unsigned char*) sBufferEn, I_LINE_PEM, 0);
	printf("Encrypted text:\n");
	printf("%s\n", sBufferEn);
	printf("%d\n", iEncodedSize);
	iDecodedSize = decrypt((unsigned char*) sBufferEn, iEncodedSize,
			(unsigned char*) sBufferDe);
	printf("Decrypted text: %s\n", sBufferDe);
	printf("%d\n", iDecodedSize);
	printf(
			"-----------------------------------------------------------------------\n");
	printf("Encryption with text as a key: %s\n", "ThisIsTheKey1");
	setEncryptionAsString((unsigned char*) "ThisIsTheKey1", S_ALPHABET_QWERTY);
	printf("B64 code table: %s\n", cAlphabet);
	iEncodedSize = encrypt((unsigned char*) sTest, strlen(sTest),
			(unsigned char*) sBufferEn, I_LINE_MIME, 0);
	printf("Encrypted text:\n");
	printf("%s\n", sBufferEn);
	printf("%d\n", iEncodedSize);
	iDecodedSize = decrypt((unsigned char*) sBufferEn, iEncodedSize,
			(unsigned char*) sBufferDe);
	printf("Decrypted text: %s\n", sBufferDe);
	printf("%d\n", iDecodedSize);
	printf(
			"-----------------------------------------------------------------------\n");
	iCryptKeySize = 1;
	printf("Encryption with int[0] as a key:");
	for (int i = 0; i < iCryptKeySize; ++i) {
		printf(" 0x%x", iCryptKey[i]);
	}
	printf("\n");
	setEncryption(iCryptKey, iCryptKeySize, S_ALPHABET_STANDARD);
	printf("B64 code table: %s\n", cAlphabet);
	iEncodedSize = encrypt((unsigned char*) sTest, strlen(sTest),
			(unsigned char*) sBufferEn, 80, 1);
	printf("Encrypted text:\n");
	printf("%s\n", sBufferEn);
	printf("%d\n", iEncodedSize);
	iDecodedSize = decrypt((unsigned char*) sBufferEn, iEncodedSize,
			(unsigned char*) sBufferDe);
	printf("Decrypted text: %s\n", sBufferDe);
	printf("%d\n", iDecodedSize);
	printf(
			"-----------------------------------------------------------------------\n");

	int iTS = currentTimeMillis();
	long iExperiments = 1234567;
	int iProgressPrev = 0;
	int iProgress = 0;
	int iMsgSize = 80;
	for (long i = 0; i < iExperiments; ++i) {
		iMsgSize = i % 256;
		iCryptKey[0] = currentTimeMillis();
		iCryptKey[1] = currentTimeMillis();
		iCryptKey[2] = currentTimeMillis();
		setEncryption(iCryptKey, 3, S_ALPHABET_QWERTY);
		for (int i1 = 0; i1 < iMsgSize; ++i1) {
			sBufferDe[i1] = (unsigned char) (i1 + i);
		}
		int iLineLength = (iCryptKey[1] & 0x3f);
		int bPadding = (iCryptKey[2] & 1) == 1;
		iEncodedSize = encrypt((unsigned char*) sBufferDe, iMsgSize,
				(unsigned char*) sBufferEn, iLineLength, bPadding);
		iDecodedSize = decrypt((unsigned char*) sBufferEn, iEncodedSize,
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

