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
    static char b64_code[65];
    static int b64_index[65];
    static bool bInitialized;
    static int b64_int(int ch) {
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
        return -1;
    }
    static int rotl16(int n, int c) {
        n = n & 0xFFFF;
        c &= 15;
        return ((n << c) | (n >> (16 - c))) & 0xFFFF;
    }
    static int rotr16(int n, int c) {
        n = n & 0xFFFF;
        c &= 15;
        return ((n >> c) | (n << (16 - c))) & 0xFFFF;
    }
    static int b64_int_from_index(int ch) {
        if (ch == 61) {
            return 64;
        } else {
            return b64_index[b64_int(ch)];
        }
    }
    static void b64_shuffle(int iKey) {
        int iDither = 0x5aa5;
        for (int i = 0; i < 64; ++i) {
            iKey = rotl16(iKey, 1);
            iDither = rotr16(iDither, 1);
            int iSwitchIndex = i + (iKey ^ iDither) % (64 - i);
            char iA = b64_code[i];
            b64_code[i] = b64_code[iSwitchIndex];
            b64_code[iSwitchIndex] = iA;
        }
        for (int i = 0; i < 64; ++i) {
            b64_index[b64_int(b64_code[i])] = i;
        }
    }
    static void b64_init(int iKey) {
        char sB64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; ++i) {
            b64_index[i] = i & 0xff;
            b64_code[i] = sB64Chars[i];
        }
        b64_code[64] = 0;
        b64_shuffle(iKey);
        bInitialized = true;
    }
    static int b64e_size(int in_size) {
        return ((in_size - 1) / 3) * 4 + 4;
    }
    static int b64d_size(int in_size) {
        return ((3 * in_size) / 4);
    }
    static int b64_encode(char* in, int in_len, char* out) {
        if (!bInitialized) {
            b64_init(0);
        }
        int i = 0, j = 0, k = 0;
        int s[3];
        int iDither = 0xa55a;
        int iG = 0;
        for (i = 0; i < in_len; i++) {
            iG = (((in[i] ^ iDither) & 0xff) & 0xff);
            s[j] = iG;
            ++j;
            iDither = rotr16(iDither, 1) ^ iG;

            if (j == 3) {
                out[k + 0] = b64_code[(s[0] & 255) >> 2];
                out[k + 1] = b64_code[((s[0] & 0x03) << 4) + ((s[1] & 0xF0) >> 4)];
                out[k + 2] = b64_code[((s[1] & 0x0F) << 2) + ((s[2] & 0xC0) >> 6)];
                out[k + 3] = b64_code[s[2] & 0x3F];
                j = 0;
                k += 4;
            }
        }
        if (j != 0) {
            if (j == 1) {
                s[1] = 0;
            }
            out[k + 0] = b64_code[(s[0] & 255) >> 2];
            out[k + 1] = b64_code[((s[0] & 0x03) << 4) + ((s[1] & 0xF0) >> 4)];
            if (j == 2) {
                out[k + 2] = b64_code[((s[1] & 0x0F) << 2)];
            } else {
                out[k + 2] = '=';
            }
            out[k + 3] = '=';
            k += 4;
        }
        out[k] = '\0';
        return k;
    }
    static int b64_decode(char* in, int in_len, char* out) {
        if (!bInitialized) {
            b64_init(0);
        }
        int j = 0, k = 0;
        int s[4];
        int iDither = 0xa55a;
        int iG = 0;
        for (int i = 0; i < in_len; ++i) {
            s[j++] = b64_int_from_index(in[i]);
            if (j == 4) {
                if (s[1] != 64) {
                    out[k + 0] = (((s[0] & 255) << 2) + ((s[1] & 0x30) >> 4));
                    if (s[2] != 64) {
                        out[k + 1] = (((s[1] & 0x0F) << 4) + ((s[2] & 0x3C) >> 2));
                        if (s[3] != 64) {
                            out[k + 2] = (((s[2] & 0x03) << 6) + (s[3]));
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

        for (int i = 0; i < k; ++i) {
            iG = out[i] & 0xff;
            out[i] = (((out[i] ^ iDither) & 0xff) & 0xff);
            iDither = rotr16(iDither, 1) ^ iG;
        }
        out[k] = '\0';
        return k;
    }
public:
    static void main() {
        std::cout << "B64 encryptor demonstration" << std::endl;
        int iCryptKey = 128;
        b64_init(iCryptKey);
        std::cout << "Crypt key: 0x" << std::hex << iCryptKey << std::endl;
        std::cout << "B64 code table: " << b64_code << std::endl;
        char sTest[] = "000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.";
        char sBufferDe[256];
        char sBufferEn[256 * 4 / 3 + 1];
        int iSourceSize = 0;
        int iEncodedSize = 0;
        int iDecodedSize = 0;
        iSourceSize = strlen(sTest);
        std::cout << "Plain text: " << sTest << std::endl;
        std::cout << iSourceSize << std::endl;
        iEncodedSize = b64_encode(sTest, iSourceSize, sBufferEn);
        std::cout << "Crypt text: " << sBufferEn << std::endl;
        std::cout << iEncodedSize << std::endl;
        iDecodedSize = b64_decode(sBufferEn, iEncodedSize, sBufferDe);
        std::cout << "Decrypt text: " << sBufferDe << std::endl;
        std::cout << iDecodedSize << std::endl;
        int iTS = static_cast<int>(std::time(nullptr));
        long iExperiments = 12345678;
        int iProgressPrev = 0;
        int iProgress = 0;
        int iMsgSize = 80;

        for (long i = 0; i < iExperiments; ++i) {
            iMsgSize = static_cast<int>(i % 256);
            iCryptKey = static_cast<int>(std::time(nullptr));
            b64_init(iCryptKey);
            for (int i1 = 0; i1 < iMsgSize; ++i1) {
                sBufferDe[i1] = static_cast<char>(i1 + i);
            }
            iEncodedSize = b64_encode(sBufferDe, iMsgSize, sBufferEn);
            iDecodedSize = b64_decode(sBufferEn, iEncodedSize, sBufferDe);
            for (int i1 = 0; i1 < iMsgSize; ++i1) {
                if (sBufferDe[i1] != static_cast<char>(i1 + i)) {
                    std::cout << "ERR: " << i << ", " << sBufferEn << std::endl;
                    return;
                }
            }
            iProgress = static_cast<int>(i * 100 / iExperiments);
            if (iProgressPrev != iProgress) {
                std::cout << "Progress: " << iProgress << "%, " << std::string(sBufferEn).substr(0, std::string(sBufferEn).find('\0')) << std::endl;
                iProgressPrev = iProgress;
            }
        }
        std::cout << "Time (millis): " << (static_cast<int>(std::time(nullptr)) - iTS) << std::endl;
    }
};

char B64Encryptor::b64_code[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int B64Encryptor::b64_index[65];
bool B64Encryptor::bInitialized = false;

int main() {
    B64Encryptor::main();
    return 0;
}


