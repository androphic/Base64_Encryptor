#============================================================================
# Name        : test.py
# Author      : Tofig Kareemov
# Version     :
# Copyright   : Your copyright notice
# Description : C64 Encryptor for Python. Test
#============================================================================
import time
import random
import c64

def currentTimeMillis():
    return int(time.time() * 1000)

def printArrayAsString(Arr, Length):
    sOutput = ""
    for i in range(Length):
        if isinstance(Arr[i], int):
            sOutput += chr(Arr[i])
        else:     
            sOutput += chr(ord(Arr[i]))
    print(sOutput)

def main():
    o = c64.C64()
    print("B64 encryptor demonstration")

    # Print left rotations
    print("Left Rotations:")
    for i in range(32):
        print(" " + str(o.rotl16(0xa5, i)) + ", ")

    # Print right rotations
    print("Right Rotations:")
    for i in range(32):
        print(" " + str(o.rotr16(0xa5, i)) + ", ")

    print("-----------------------------------------------------------------------")

    sTest = b"000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov."
    sBufferDe = bytearray(256)
    sBufferEn = bytearray(256 * 2)
    iSourceSize = 0
    iEncodedLen = 0
    iDecodedLen = 0
    iSourceSize = len(sTest)
    iCryptKey = [128, 12345, 67890]

    print("Plain text:", sTest.decode("utf-8"))
    print(iSourceSize)
    print("-----------------------------------------------------------------------")

    print("Standard Base64 encoding")
    o.setEncryption(None, 0, c64.C64.S_ALPHABET_STANDARD)
    print("B64 code table:", o.cAlphabet)
    print("B64 code index table:", o.iAlphabetIndex)

    iEncodedLen = o.encrypt(sTest, len(sTest), sBufferEn, 17, True)
    print("Standard Base64 encoded text:")
    print(sBufferEn[:iEncodedLen].decode("utf-8"))
    print(iEncodedLen)

    iDecodedLen = o.decrypt(sBufferEn, iEncodedLen, sBufferDe)
    print("Standard Base64 decoded text:")
    print(sBufferDe[:iDecodedLen].decode("utf-8"))
    print(iDecodedLen)

    print("-----------------------------------------------------------------------")

    sBufferDe = bytearray(256)
    sBufferEn = bytearray(256 * 4 // 3 + 1)

    print("Encryption with int[] as key:", iCryptKey)
    o.setEncryption(iCryptKey, len(iCryptKey), c64.C64.S_ALPHABET_URL)
    print("B64 code table:", o.cAlphabet)
    print("B64 code index table:", o.iAlphabetIndex)

    iEncodedLen = o.encrypt(sTest, len(sTest), sBufferEn, c64.C64.I_LINE_PEM, False)
    print("Encrypted text:")
    print(sBufferEn[:iEncodedLen].decode("utf-8"))
    print(iEncodedLen)

    iDecodedLen = o.decrypt(sBufferEn, iEncodedLen, sBufferDe)
    print("Decrypted text:")
    print(sBufferDe[:iDecodedLen].decode("utf-8"))
    print(iDecodedLen)

    print("-----------------------------------------------------------------------")

    sBufferDe = bytearray(256)
    sBufferEn = bytearray(256 * 4 // 3 + 1)

    print("Encryption with String as key:", "ThisIsTheKey1")
    o.setEncryptionAsString("ThisIsTheKey1", c64.C64.S_ALPHABET_QWERTY)
    print("B64 code table:", o.cAlphabet)
    print("B64 code index table:", o.iAlphabetIndex)

    iEncodedLen = o.encrypt(sTest, len(sTest), sBufferEn, c64.C64.I_LINE_MIME, False)
    print("Encrypted text:")
    print(sBufferEn[:iEncodedLen].decode("utf-8"))
    print(iEncodedLen)

    iDecodedLen = o.decrypt(sBufferEn, iEncodedLen, sBufferDe)
    print("Decrypted text:")
    print(sBufferDe[:iDecodedLen].decode("utf-8"))
    print(iDecodedLen)

    print("-----------------------------------------------------------------------")

    sBufferDe = bytearray(256)
    sBufferEn = bytearray(256 * 4 // 3 + 1)

    print("Encryption with int[0] as key:", iCryptKey[0])
    o.setEncryption([iCryptKey[0]], 1, c64.C64.S_ALPHABET_STANDARD)
    print("B64 code table:", o.cAlphabet)
    print("B64 code index table:", o.iAlphabetIndex)

    iEncodedLen = o.encrypt(sTest, len(sTest), sBufferEn, 80, True)
    print("Encrypted text:")
    print(sBufferEn[:iEncodedLen].decode("utf-8"))
    print(iEncodedLen)

    iDecodedLen = o.decrypt(sBufferEn, iEncodedLen, sBufferDe)
    print("Decrypted text:")
    print(sBufferDe[:iDecodedLen].decode("utf-8"))
    print(iDecodedLen)

    print("-----------------------------------------------------------------------")

    sBufferDe = bytearray(256)
    sBufferEn = bytearray(256 * 2)
    iTS = int(time.time() * 1000)
    iExperiments = 12345
    iProgressPrev = 0
    iProgress = 0
    iMsgSize = 80

    for i in range(iExperiments):
        iMsgSize = int(i % 256)
        iCryptKey[0] = int(time.time() * 1000)
        iCryptKey[1] = int(time.time() * 1000)
        iCryptKey[2] = int(time.time() * 1000)

        o.setEncryption(iCryptKey, 3, c64.C64.S_ALPHABET_QWERTY)
        o.resetStates()
        sBufferDe[:iMsgSize] = [(i1 + i) & 0xFF for i1 in range(iMsgSize)]

        iLineLength = iCryptKey[1] & 0x3F
        bPadding = (iCryptKey[2] & 1) == 1

        iEncodedLen = o.encrypt(sBufferDe, iMsgSize, sBufferEn, iLineLength, bPadding)
        iDecodedLen = o.decrypt(sBufferEn, iEncodedLen, sBufferDe)
        iCalc = o.calcEncryptedLen(iMsgSize, iLineLength, bPadding)

        if iCalc != iEncodedLen:
            print(f"ERR: Enc size calc is not correct, expected {iCalc} ({iMsgSize}, {iLineLength}, {bPadding}), real {iEncodedLen}")
            return

        iCalc = o.calcDecryptedLen(iEncodedLen, iLineLength, bPadding)
        if not (iCalc >= iDecodedLen and iCalc < (iDecodedLen + 3)):
            print(f"ERR: Dec size calc is not correct, expected {iCalc} ({iEncodedLen}, {iLineLength}, {bPadding}), real {iDecodedLen}")
            return

        for i1 in range(iMsgSize):
            if sBufferDe[i1] != ((i1 + i) & 0xFF):
                print(f"ERR: {i}, {sBufferEn}")
                return

        iProgress = int(i * 100 / iExperiments)
        if iProgressPrev != iProgress:
            print(f"Progress: {iProgress}%")
            printArrayAsString(sBufferEn, iEncodedLen)
            iProgressPrev = iProgress

    print("Time (millis):", int(time.time() * 1000) - iTS)

if __name__ == "__main__":
    main()
