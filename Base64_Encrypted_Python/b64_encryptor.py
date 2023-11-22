#============================================================================
# Name        : Base64_Encrypted_Python.py
# Author      : Tofig Kareemov
# Version     :
# Copyright   : Your copyright notice
# Description : Base64 Encryptor for Python
#============================================================================

import sys  
import time

def currentTimeMillis():
    return int(time.time() * 1000)


class B64Encryptor:
    b64_code = [0] * 65 #"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    b64_index = [0] * 65
    bInitialized = False

    @staticmethod
    def b64_int(ch):
        if isinstance(ch, str):
            ch = ord(ch)
        if ch == 61:
            return 64
        elif ch == 43:
            return 62
        elif ch == 47:
            return 63
        elif ch > 47 and ch < 58:
            return ch + 4
        elif ch > 64 and ch < 91:
            return ch - ord('A')
        elif ch > 96 and ch < 123:
            return (ch - ord('a')) + 26
        return 64

    @staticmethod
    def rotl16(n, c):
        n = n & 0xFFFF
        c &= 15
        return ((n << c) | (n >> (16 - c))) & 0xFFFF

    @staticmethod
    def rotr16(n, c):
        n = n & 0xFFFF
        c &= 15
        return ((n >> c) | (n << (16 - c))) & 0xFFFF

    @staticmethod
    def b64_int_from_index(ch):
        if ch == 61:
            return 64
        else:
            return B64Encryptor.b64_index[B64Encryptor.b64_int(ch)]

    @staticmethod
    def b64_shuffle(iKey):
        iDither = 0x5aa5
        for i in range(64):
            iKey = B64Encryptor.rotl16(iKey, 1)
            iDither = B64Encryptor.rotr16(iDither, 1)
            iSwitchIndex = i + (iKey ^ iDither) % (64 - i)
            iA = B64Encryptor.b64_code[i]
            B64Encryptor.b64_code[i] = B64Encryptor.b64_code[iSwitchIndex]
            B64Encryptor.b64_code[iSwitchIndex] = iA
        for i in range(64):
            B64Encryptor.b64_index[B64Encryptor.b64_int(B64Encryptor.b64_code[i])] = i

    @staticmethod
    def b64_init(iKey):
        sB64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for i in range(64):
            B64Encryptor.b64_index[i] = i & 0xff
            B64Encryptor.b64_code[i] = sB64Chars[i]
        B64Encryptor.b64_code[64] = 0
        B64Encryptor.b64_shuffle(iKey)
        B64Encryptor.bInitialized = True

    @staticmethod
    def b64e_size(in_size):
        return ((in_size - 1) // 3) * 4 + 4

    @staticmethod
    def b64d_size(in_size):
        return (3 * in_size) // 4

    @staticmethod
    def b64_encode(in_str, in_len, out_str):
        if not B64Encryptor.bInitialized:
            B64Encryptor.b64_init(0)
        i = 0
        j = 0
        k = 0
        s = [0] * 3
        iDither = 0xa55a
        iG = 0
        for i in range(in_len):
            iG = (((ord(in_str[i]) ^ iDither) & 0xff) & 0xff)
            s[j] = iG
            j += 1
            iDither = B64Encryptor.rotr16(iDither, 1) ^ iG
            # s[j] = ord(in_str[i])
            # j += 1

            if j == 3:
                out_str[k + 0] = B64Encryptor.b64_code[(s[0] & 255) >> 2]
                out_str[k + 1] = B64Encryptor.b64_code[((s[0] & 0x03) << 4) + ((s[1] & 0xF0) >> 4)]
                out_str[k + 2] = B64Encryptor.b64_code[((s[1] & 0x0F) << 2) + ((s[2] & 0xC0) >> 6)]
                out_str[k + 3] = B64Encryptor.b64_code[s[2] & 0x3F]
                j = 0
                k += 4
        if j != 0:
            if j == 1:
                s[1] = 0
            out_str[k + 0] = B64Encryptor.b64_code[(s[0] & 255) >> 2]
            out_str[k + 1] = B64Encryptor.b64_code[((s[0] & 0x03) << 4) + ((s[1] & 0xF0) >> 4)]
            if j == 2:
                out_str[k + 2] = B64Encryptor.b64_code[((s[1] & 0x0F) << 2)]
            else:
                out_str[k + 2] = '='
            out_str[k + 3] = '='
            k += 4
        out_str[k] = '\0'
        return k

    @staticmethod
    def b64_decode(in_str, in_len, out_str):
        if not B64Encryptor.bInitialized:
            B64Encryptor.b64_init(0)
        j = 0
        k = 0
        s = [0] * 4
        iDither = 0xa55a
        iG = 0
        for i in range(in_len):
            s[j] = B64Encryptor.b64_int_from_index(ord(in_str[i]))
            j += 1
            if j == 4:
                if s[1] != 64:
                    out_str[k + 0] = (((s[0] & 255) << 2) + ((s[1] & 0x30) >> 4))
                    if s[2] != 64:
                        out_str[k + 1] = (((s[1] & 0x0F) << 4) + ((s[2] & 0x3C) >> 2))
                        if s[3] != 64:
                            out_str[k + 2] = (((s[2] & 0x03) << 6) + (s[3]))
                            k += 3
                        else:
                            k += 2
                    else:
                        k += 1
                j = 0

        for i in range(k):
            if isinstance(out_str[i], str):
               out_str[i] = ord(out_str[i])
            iG = out_str[i] & 0xff
            out_str[i] = (((out_str[i] ^ iDither) & 0xff) & 0xff)
            iDither = B64Encryptor.rotr16(iDither, 1) ^ iG
        out_str[k] = '\0'
        return k

    @staticmethod
    def main():
        print("B64 encryptor demonstration")
        iCryptKey = 128
        B64Encryptor.b64_init(iCryptKey)
        print("Crypt key: 0x{:x}".format(iCryptKey))
        print("B64 code table: {}".format(B64Encryptor.b64_code))
        sTest = "000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov."
        sBufferDe = [0] * 256
        sBufferEn = [0] * (256 * 4 // 3)
        iSourceSize = 0
        iEncodedSize = 0
        iDecodedSize = 0
        iSourceSize = len(sTest)
        print("Plain text: {}".format(sTest))
        print(iSourceSize)
        iEncodedSize = B64Encryptor.b64_encode(sTest, iSourceSize, sBufferEn)
        print("Crypt text: {}".format(sBufferEn))
        print(iEncodedSize)
        iDecodedSize = B64Encryptor.b64_decode(sBufferEn, iEncodedSize, sBufferDe)
        #print("Decrypt text: %s".format(''.join(chr(i) for i in sBufferDe)))
        sOutput = ""
        for i in range(iDecodedSize):
            sOutput += chr(sBufferDe[i])
        print("Decrypt text: " + sOutput)
        #print("".join(str(i) for i in sBufferDe))
        #print (list(map(chr,sBufferDe)))
        print(iDecodedSize)
        iTS = int(time.time())
        iExperiments = 12345
        iProgressPrev = 0
        iProgress = 0
        iMsgSize = 80

        for i in range(iExperiments):
            iMsgSize = i % 256
            iCryptKey = int(time.time())
            B64Encryptor.b64_init(iCryptKey)
            for i1 in range(iMsgSize):
                sBufferDe[i1] = chr((i1 + i) & 0xff)
            iEncodedSize = B64Encryptor.b64_encode(sBufferDe, iMsgSize, sBufferEn)
            iDecodedSize = B64Encryptor.b64_decode(sBufferEn, iEncodedSize, sBufferDe)
            for i1 in range(iMsgSize):
                if sBufferDe[i1] != ((i1 + i) & 0xff):
                    print("ERR[{},{}]: {}, [{},{},{}]".format(i,i1, sBufferEn, iMsgSize, iEncodedSize, iDecodedSize))
                    return
            iProgress = int(i * 100 / iExperiments)
            if iProgressPrev != iProgress:
                sOutput = ""
                for i in range(iEncodedSize):
                    sOutput += sBufferEn[i]
                print("Progress: {}%, {}".format(iProgress, sOutput))
                iProgressPrev = iProgress
        print("Time (millis): {}".format(int(time.time()) - iTS))

if __name__ == "__main__":
    B64Encryptor.main()