/*
 ============================================================================
 Name        : b64_encryptor.c
 Author      : Tofig Kareemov
 Version     :
 Copyright   : Your copyright notice
 Description : Base64 Encryptor in C
 ============================================================================
 */

#include "b64_encryptor.h"

/**************************************************************************/
int main(void)
/**************************************************************************/
{
	printf("B64 encryptor demonstration\n");
//	unsigned int iCryptKey[] = {128, 256, 1024};
	unsigned int iCryptKey[] = {128};
	int iCryptKeySize = sizeof(iCryptKey)/sizeof(iCryptKey[0]);
	const char sTest[256] =
			"000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.";
	unsigned char sBufferDe[256] = { 0 };
	unsigned char sBufferEn[256 * 4 / 3 + 1] = { 0 };
	int iSourceSize = 0;
	int iEncodedSize = 0;
	int iDecodedSize = 0;

	iSourceSize = strlen(sTest);
	printf("Plain text: %s\n", sTest);
	printf("%d\n", iSourceSize);
	printf("-----------------------------------------------------------------------\n");

	b64_init(0,0);
	printf("B64 code table: %s\n", b64_code);
	iEncodedSize = b64_encode((unsigned char*) sTest, strlen(sTest),
			(unsigned char*) sBufferEn);
	printf("Standard Base64 encoded text: %s\n", sBufferEn);
	printf("%d\n", iEncodedSize);
	iDecodedSize = b64_decode((unsigned char*) sBufferEn, iEncodedSize,
			(unsigned char*) sBufferDe);
	printf("Standard Base64 decoded text: %s\n", sBufferDe);
	printf("%d\n", iDecodedSize);
	printf("-----------------------------------------------------------------------\n");

	printf("Encryption with int[] as a key:");
	for (int i=0;i<iCryptKeySize;++i){
		printf(" 0x%x", iCryptKey[i]);
	}
	printf("\n");
	b64_init(iCryptKey,iCryptKeySize);
	printf("B64 code table: %s\n", b64_code);
	iEncodedSize = b64_encode((unsigned char*) sTest, strlen(sTest),
			(unsigned char*) sBufferEn);
	printf("Encrypted text: %s\n", sBufferEn);
	printf("%d\n", iEncodedSize);
	iDecodedSize = b64_decode((unsigned char*) sBufferEn, iEncodedSize,
			(unsigned char*) sBufferDe);
	printf("Decrypted text: %s\n", sBufferDe);
	printf("%d\n", iDecodedSize);
	printf("-----------------------------------------------------------------------\n");

	printf("Encryption with text as a key: %s\n", "ThisIsTheKey");
	b64_init_string("ThisIsTheKey");
	printf("B64 code table: %s\n", b64_code);
	iEncodedSize = b64_encode((unsigned char*) sTest, strlen(sTest),
			(unsigned char*) sBufferEn);
	printf("Encrypted text: %s\n", sBufferEn);
	printf("%d\n", iEncodedSize);
	iDecodedSize = b64_decode((unsigned char*) sBufferEn, iEncodedSize,
			(unsigned char*) sBufferDe);
	printf("Decrypted text: %s\n", sBufferDe);
	printf("%d\n", iDecodedSize);
	printf("-----------------------------------------------------------------------\n");

	int iTS = currentTimeMillis();
	long iExperiments = 123456;
	int iProgressPrev = 0;
	int iProgress = 0;
	int iMsgSize = 80;
	for (long i = 0; i < iExperiments; ++i) {
		iMsgSize = i % 256;
		iCryptKey[0] = currentTimeMillis();
		b64_init(iCryptKey,1);
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


