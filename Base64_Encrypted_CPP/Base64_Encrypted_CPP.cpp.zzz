//============================================================================
// Name        : Base64_Encrypted_CPP.cpp
// Author      : Tofig Kareemov
// Version     :
// Copyright   : Your copyright notice
// Description : C++ implementation of Base64 Encryptor
//============================================================================

#include <iostream>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <algorithm>
using namespace std;

class B64Encryptor {
private:
	char iB64Code[65];
	int iB64Index[65];
	bool bB64Initialized;
	bool bB64ToGlue;

	int mb64_int(int ch) {
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

	int mb64_rotl16(int n, int c) {
		n = n & 0xFFFF;
		c &= 15;
		return ((n << c) | (n >> (16 - c))) & 0xFFFF;
	}

	int mb64_rotr16(int n, int c) {
		n = n & 0xFFFF;
		c &= 15;
		return ((n >> c) | (n << (16 - c))) & 0xFFFF;
	}

	int mb64_int_from_index(int ch) {
		int iCh = mb64_int(ch);
		if (iCh == 255) {
			return 255;
		}
		if (ch == 61) {
			return 64;
		} else {
			return iB64Index[iCh];
		}
	}

	void mb64_shuffle(int iKey) {
		int iDither = 0x5aa5;
		for (int i = 0; i < 64; ++i) {
			iKey = mb64_rotl16(iKey, 1);
			iDither = mb64_rotr16(iDither, 1);
			int iSwitchIndex = i + (iKey ^ iDither) % (64 - i);
			char iA = iB64Code[i];
			iB64Code[i] = iB64Code[iSwitchIndex];
			iB64Code[iSwitchIndex] = iA;
		}
	}

	void mb64_init_tables() {
		const char *sB64Chars =
				"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		bB64ToGlue = 0;
		bB64Initialized = 0;
		for (int i = 0; i < 64; ++i) {
			iB64Index[i] = i & 0xff;
			iB64Code[i] = sB64Chars[i];
		}
		iB64Code[64] = 0;
	}

	void mb64_index_tables() {
		for (int i = 0; i < 64; ++i) {
			iB64Index[mb64_int(iB64Code[i])] = i;
		}
	}

public:
	void b64_set_key_i(int iKey[], int iSize) {
		mb64_init_tables();
		if (iKey != nullptr) {
			for (int i = 0; i < iSize; ++i) {
				mb64_shuffle(iKey[i]);
			}
			mb64_index_tables();
			bB64ToGlue = true;
		}
		bB64Initialized = true;
	}

	void b64_set_key_s(std::string sKey) {
		mb64_init_tables();
		if (!sKey.empty()) {
			for(std::string::size_type i = 0; i < sKey.size(); ++i) {
				mb64_shuffle(0 | sKey[i] | (sKey[i] << 8));
			}
			mb64_index_tables();
			bB64ToGlue = true;
		}
		bB64Initialized = true;
	}

	int b64_enc_size(int in_size) {
		return ((in_size - 1) / 3) * 4 + 4;
	}

	int b64_dec_size(int in_size) {
		return ((3 * in_size) / 4);
	}

	int b64_encode(const char in[], int in_len, char out[],
			int iTextLineLength) {
		if (!bB64Initialized) {
			b64_set_key_i(nullptr, 0);
		}
		int i = 0, j = 0, k = 0;
		int s[3];
		int iDitherR = 0xa55a;
		int iDitherL = 0x55aa;
		int iG = 0;
		int iTextLineCount = 0;
		iTextLineLength = (iTextLineLength / 4) * 4;
		for (i = 0; i < in_len; i++) {
			if (bB64ToGlue) {
				iG = ((in[i] ^ (iDitherL & 0xff)) & 0xff);
				s[j] = iG;
				iDitherR = mb64_rotr16(iDitherR, 1) ^ iG;
				iDitherL = mb64_rotl16(iDitherL, 1) ^ iDitherR;
			} else {
				s[j] = (char) (in[i]);
			}
			++j;
			if (j == 3) {
				out[k + 0] = (char) iB64Code[(s[0] & 255) >> 2];
				out[k + 1] = (char) iB64Code[((s[0] & 0x03) << 4)
						| ((s[1] & 0xF0) >> 4)];
				out[k + 2] = (char) iB64Code[((s[1] & 0x0F) << 2)
						| ((s[2] & 0xC0) >> 6)];
				out[k + 3] = (char) iB64Code[s[2] & 0x3F];
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
		if (j != 0) {
			if (j == 1) {
				s[1] = 0;
			}
			out[k + 0] = (char) iB64Code[(s[0] & 255) >> 2];
			out[k + 1] = (char) iB64Code[((s[0] & 0x03) << 4)
					| ((s[1] & 0xF0) >> 4)];
			if (j == 2) {
				out[k + 2] = (char) iB64Code[((s[1] & 0x0F) << 2)];
			} else {
				out[k + 2] = '=';
			}
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

	int b64_decode(const char in[], int in_len, char out[]) {
		if (!bB64Initialized) {
			b64_set_key_i(nullptr, 0);
		}
		int j = 0, k = 0;
		int s[4];
		int iDitherR = 0xa55a;
		int iDitherL = 0x55aa;
		int iG = 0;
		for (int i = 0; i < in_len; ++i) {
			s[j] = mb64_int_from_index(in[i]);
			if (s[j] != 255) {
				++j;
				if (j == 4) {
					if (s[1] != 64) {
						out[k + 0] = (char) (((s[0] & 255) << 2)
								| ((s[1] & 0x30) >> 4));
						if (s[2] != 64) {
							out[k + 1] = (char) (((s[1] & 0x0F) << 4)
									| ((s[2] & 0x3C) >> 2));
							if (s[3] != 64) {
								out[k + 2] = (char) (((s[2] & 0x03) << 6)
										| (s[3]));
								k += 3;
							} else {
								k += 2;
							}
						} else {
							k += 1;
						}
					}
					j = 0;
				}
			}
		}
		if (bB64ToGlue) {
			for (int i = 0; i < k; ++i) {
				iG = out[i] & 0xff;
				out[i] = (char) ((out[i] ^ (iDitherL & 0xff)) & 0xff);
				iDitherR = mb64_rotr16(iDitherR, 1) ^ iG;
				iDitherL = mb64_rotl16(iDitherL, 1) ^ iDitherR;
			}
		}
		out[k] = '\0';
		return k;
	}
public:
	B64Encryptor() {
		bB64Initialized = false;
		bB64ToGlue = false;
	}
	;

	void main() {
		std::cout << "B64 encryptor demonstration" << std::endl;
		int iCryptKey[] = { 128, 12345, 67890 };
		char sTest[] =
				"000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.";
		char sBufferDe[256];
		char sBufferEn[256 * 4 / 3 + 1];
		int iSourceSize = 0;
		int iEncodedSize = 0;
		int iDecodedSize = 0;
		iSourceSize = strlen(sTest);

		std::cout << "Plain text: " << sTest << std::endl;
		std::cout << iSourceSize << std::endl;
		std::cout << "-----------------------------------------------------------------------" << std::endl;

		b64_set_key_i(0, 0);
		std::cout << "B64 code table: " << iB64Code << std::endl;
		iEncodedSize = b64_encode(sTest, iSourceSize, sBufferEn, 16);
		std::cout << "Crypt text: \n" << sBufferEn << std::endl;
		std::cout << std::dec << iEncodedSize << std::endl;
		iDecodedSize = b64_decode(sBufferEn, iEncodedSize, sBufferDe);
		std::cout << "Decrypt text: " << sBufferDe << std::endl;
		std::cout << std::dec << iDecodedSize << std::endl;
		std::cout << "-----------------------------------------------------------------------" << std::endl;

		b64_set_key_i(iCryptKey, 3);
		std::cout << "Crypt key: " << iCryptKey[0] << " " << iCryptKey[1] << " " << iCryptKey[2] << std::endl;
		std::cout << "B64 code table: " << iB64Code << std::endl;
		iEncodedSize = b64_encode(sTest, iSourceSize, sBufferEn, 32);
		std::cout << "Crypt text: \n" << sBufferEn << std::endl;
		std::cout << std::dec << iEncodedSize << std::endl;
		iDecodedSize = b64_decode(sBufferEn, iEncodedSize, sBufferDe);
		std::cout << "Decrypt text: " << sBufferDe << std::endl;
		std::cout << std::dec << iDecodedSize << std::endl;
		std::cout << "-----------------------------------------------------------------------" << std::endl;

		b64_set_key_s("ThisIsTheKey1");
		std::cout << "Crypt key: " << "ThisIsTheKey1" << std::endl;
		std::cout << "B64 code table: " << iB64Code << std::endl;
		iEncodedSize = b64_encode(sTest, iSourceSize, sBufferEn, 64);
		std::cout << "Crypt text: \n" << sBufferEn << std::endl;
		std::cout << std::dec << iEncodedSize << std::endl;
		iDecodedSize = b64_decode(sBufferEn, iEncodedSize, sBufferDe);
		std::cout << "Decrypt text: " << sBufferDe << std::endl;
		std::cout << std::dec << iDecodedSize << std::endl;
		std::cout << "-----------------------------------------------------------------------" << std::endl;

		b64_set_key_i(iCryptKey, 1);
		std::cout << "Crypt key: 0x" << std::hex << iCryptKey[0] << std::endl;
		std::cout << "B64 code table: " << iB64Code << std::endl;
		iEncodedSize = b64_encode(sTest, iSourceSize, sBufferEn, 80);
		std::cout << "Crypt text: \n" << sBufferEn << std::endl;
		std::cout << std::dec << iEncodedSize << std::endl;
		iDecodedSize = b64_decode(sBufferEn, iEncodedSize, sBufferDe);
		std::cout << "Decrypt text: " << sBufferDe << std::endl;
		std::cout << std::dec << iDecodedSize << std::endl;
		std::cout << "-----------------------------------------------------------------------" << std::endl;


		int iTS = static_cast<int>(std::time(nullptr));
		long iExperiments = 1234567;
		int iProgressPrev = 0;
		int iProgress = 0;
		int iMsgSize = 80;

		for (long i = 0; i < iExperiments; ++i) {
			iMsgSize = static_cast<int>(i % 256);
			iCryptKey[0] = static_cast<int>(std::time(nullptr));
			iCryptKey[1] = static_cast<int>(std::time(nullptr));
			iCryptKey[2] = static_cast<int>(std::time(nullptr));
			b64_set_key_i(iCryptKey, 3);
			for (int i1 = 0; i1 < iMsgSize; ++i1) {
				sBufferDe[i1] = static_cast<char>(i1 + i);
			}
			iEncodedSize = b64_encode(sBufferDe, iMsgSize, sBufferEn, 0);
			iDecodedSize = b64_decode(sBufferEn, iEncodedSize, sBufferDe);
			for (int i1 = 0; i1 < iMsgSize; ++i1) {
				if (sBufferDe[i1] != static_cast<char>(i1 + i)) {
					std::cout << "ERR: " << i << ", " << sBufferEn << std::endl;
					return;
				}
			}
			iProgress = static_cast<int>(i * 100 / iExperiments);
			if (iProgressPrev != iProgress) {
				std::cout << "Progress: " << iProgress << "%, "
						<< std::string(sBufferEn).substr(0,
								std::string(sBufferEn).find('\0')) << std::endl;
				iProgressPrev = iProgress;
			}
		}
		std::cout << "Time (millis): "
				<< (static_cast<int>(std::time(nullptr)) - iTS) << std::endl;
	}
};

int main() {
	static B64Encryptor o = B64Encryptor();
	o.main();
	return 0;
}

