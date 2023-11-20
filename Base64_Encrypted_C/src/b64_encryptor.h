/*
 ============================================================================
 Name        : b64_encryptor.h
 Author      : Tofig Kareemov
 Version     :
 Copyright   : Your copyright notice
 Description : Base64 Encryptor in C, Ansi-style
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

void b64_init(unsigned int iKey);

unsigned int b64e_size(unsigned int in_size);

unsigned int b64d_size(unsigned int in_size);

unsigned int b64_encode(const unsigned char* in, unsigned int in_len, unsigned char* out);

unsigned int b64_decode(const unsigned char* in, unsigned int in_len, unsigned char* out);

unsigned int currentTimeMillis() {
	struct timeval oTime;
	gettimeofday(&oTime, 0);
	long long iMilliseconds = oTime.tv_sec * 1000LL + oTime.tv_usec / 1000;
	return (unsigned int) iMilliseconds;
}

#endif /* B64_ENCRYPTOR_H_ */
