#============================================================================
# Name        : c64.py
# Author      : Tofig Kareemov
# Version     :
# Copyright   : Your copyright notice
# Description : C64 Encryptor for Python
#============================================================================

import sys  

class C64:
    S_ALPHABET_STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    S_ALPHABET_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
    S_ALPHABET_QWERTY = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890-_="
    S_ALPHABET_IMAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,="
    S_ALPHABET_HQX = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr="
    S_ALPHABET_CRYPT = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="
    S_ALPHABET_GEDCOM = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="
    S_ALPHABET_BCRYPT = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789="
    S_ALPHABET_XX = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="
    S_ALPHABET_BASH = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@_="

    I_LINE_STANDARD = 0
    I_LINE_MIME = 76
    I_LINE_PEM = 64

    def __init__(self):
        self.cAlphabet = [''] * 65
        self.iAlphabetIndex = [0] * 128
        self.bInitialized = False
        self.bToGlue = False
        self.oEncState = self.State()
        self.oDecState = self.State()

    class State:
        def __init__(self):
            self.iBuf = [0] * 4
            self.iB = 0
            self.iDR = 0xa55a
            self.iDL = 0x55aa
            self.iG = 0
            self.iLineLen = 0

        def init(self):
            self.iBuf = [0] * 4
            self.iB = 0
            self.iDR = 0xa55a
            self.iDL = 0x55aa
            self.iG = 0
            self.iLineLen = 0

    def rotl16(self, n, c):
        n = n & 0xFFFF
        c &= 15
        return ((n << c) | (n >> (16 - c))) & 0xFFFF

    def rotr16(self, n, c):
        n = n & 0xFFFF
        c &= 15
        return ((n >> c) | (n << (16 - c))) & 0xFFFF

    def shuffleCodeTable(self, iKey):
        iDitherForKey = 0x5aa5
        for i in range(64):
            iKey = self.rotl16(iKey, 1)
            iDitherForKey = self.rotr16(iDitherForKey, 1)
            iSwitchIndex = i + (iKey ^ iDitherForKey) % (64 - i)
            iA = self.cAlphabet[i]
            self.cAlphabet[i] = self.cAlphabet[iSwitchIndex]
            self.cAlphabet[iSwitchIndex] = iA

    def setAlphabet(self, sAlphabet):
        if sAlphabet is None or len(sAlphabet) != 65:
            self.cAlphabet = list(self.S_ALPHABET_STANDARD)
            return
        self.cAlphabet = list(sAlphabet)
        for i in range(len(self.iAlphabetIndex)):
            self.iAlphabetIndex[i] = 0
        for i in range(len(self.cAlphabet)):
            self.cAlphabet[i] = chr(ord(self.cAlphabet[i]) & 0x7f)
            if self.iAlphabetIndex[ord(self.cAlphabet[i])] == 0:
                self.iAlphabetIndex[ord(self.cAlphabet[i])] = 1
            else:
                self.cAlphabet = list(self.S_ALPHABET_STANDARD)
                return

    def initTables(self, sAlphabet):
        self.bToGlue = False
        self.bInitialized = False
        self.oEncState.init()
        self.oDecState.init()
        self.setAlphabet(sAlphabet)

    def indexTables(self):
        for i in range(len(self.iAlphabetIndex)):
            self.iAlphabetIndex[i] = 255
        for i in range(len(self.cAlphabet)):
            self.iAlphabetIndex[ord(self.cAlphabet[i])] = i

    def setEncryption(self, iKey, iKeyLength, sAlphabet):
        self.initTables(sAlphabet)
        if iKey is not None:
            if iKeyLength <= 0 or iKeyLength > len(iKey):
                iKeyLength = len(iKey)
            for i in range(iKeyLength):
                self.shuffleCodeTable(iKey[i])
            self.bToGlue = True
        self.indexTables()
        self.bInitialized = True

    def setEncryptionAsString(self, sKey, sAlphabet):
        self.initTables(sAlphabet)
        if sKey is not None:
            for char in sKey:
                self.shuffleCodeTable(0 | ord(char) | (ord(char) <<  8))
            self.bToGlue = True
        self.indexTables()
        self.bInitialized = True


    def calcEncryptedLen(self, iInputLen, iLineLength, bPadding):
        iLineLength = (iLineLength // 4) * 4
        iOutputLen = iInputLen // 3 * 4
        if iLineLength > 0:
            iOutputLen = iOutputLen + (iOutputLen // iLineLength * 2)
        if iInputLen % 3 == 1:
            iOutputLen += 2
            if bPadding:
                iOutputLen += 2
        elif iInputLen % 3 == 2:
            iOutputLen += 3
            if bPadding:
                iOutputLen += 1
        return iOutputLen

    def calcDecryptedLen(self, iInputSize, iLineLength, bPadding):
        iLineLength = (iLineLength // 4) * 4
        if iLineLength > 0:
            iInputSize = iInputSize - (iInputSize // (iLineLength + 2)) * 2
        iOutputLen = (iInputSize // 4) * 3
        if not bPadding:
            if iInputSize % 4 == 2:
                iOutputLen = iOutputLen + 1
            elif iInputSize % 4 == 3:
                iOutputLen = iOutputLen + 2
        else:
            pass
        return iOutputLen

    def resetStates(self):
        self.oEncState.init()
        self.oDecState.init()

    def encrypt(self, iIn, iInLen, iOut, iLineMaxLen, bPadding):
        if not self.bInitialized:
            self.setEncryption(None, 0, None)
        iLineMaxLen = (iLineMaxLen // 4) * 4
        o = self.oEncState
        k = 0
        for i in range(iInLen):
            if self.bToGlue:
                o.iG = (iIn[i] ^ o.iDL & 0xff) & 0xff
                o.iBuf[o.iB] = o.iG
                o.iDR = self.rotr16(o.iDR, 1) ^ o.iG
                o.iDL = self.rotl16(o.iDL, 1) ^ o.iDR
            else:
                o.iBuf[o.iB] = iIn[i]
            o.iB += 1
            if o.iB == 3:
                iOut[k + 0] = ord(self.cAlphabet[(o.iBuf[0] & 255) >> 2])
                iOut[k + 1] = ord(self.cAlphabet[((o.iBuf[0] & 0x03) << 4) | ((o.iBuf[1] & 0xF0) >> 4)])
                iOut[k + 2] = ord(self.cAlphabet[((o.iBuf[1] & 0x0F) << 2) | ((o.iBuf[2] & 0xC0) >> 6)])
                iOut[k + 3] = ord(self.cAlphabet[o.iBuf[2] & 0x3F])
                o.iB = 0
                k += 4
                o.iLineLen += 4
                if iLineMaxLen > 0:
                    if o.iLineLen >= iLineMaxLen:
                        iOut[k] = ord('\r')
                        k += 1
                        iOut[k] = ord('\n')
                        k += 1
                        o.iLineLen = 0
        if o.iB != 0:
            if o.iB == 1:
                o.iBuf[1] = 0
            iOut[k + 0] = ord(self.cAlphabet[(o.iBuf[0] & 255) >> 2])
            iOut[k + 1] = ord(self.cAlphabet[((o.iBuf[0] & 0x03) << 4) | ((o.iBuf[1] & 0xF0) >> 4)])
            k += 2
            o.iLineLen += 2
            if o.iB == 2:
                iOut[k] = ord(self.cAlphabet[((o.iBuf[1] & 0x0F) << 2)])
                k += 1
                o.iLineLen += 1
            else:
                if bPadding:
                    iOut[k] = ord(self.cAlphabet[64])
                    k += 1
                    o.iLineLen += 1
            if bPadding:
                iOut[k] = ord(self.cAlphabet[64])
                k += 1
                o.iLineLen += 1
        iOut[k] = ord('\0')
        return k

    def decrypt(self, iIn, iInLen, iOut):
        if not self.bInitialized:
            self.setEncryption(None, 0, None)
        o = self.oDecState
        k = 0
        for i in range(iInLen):
            o.iBuf[o.iB] = self.iAlphabetIndex[iIn[i]]
            if o.iBuf[o.iB] != 255:
                o.iB += 1
                if o.iB == 4:
                    if o.iBuf[0] != 64:
                        if o.iBuf[1] != 64:
                            iOut[k + 0] = (o.iBuf[0] & 255) << 2 | (o.iBuf[1] & 0x30) >> 4
                            if o.iBuf[2] != 64:
                                iOut[k + 1] = (o.iBuf[1] & 0x0F) << 4 | (o.iBuf[2] & 0x3C) >> 2
                                if o.iBuf[3] != 64:
                                    iOut[k + 2] = (o.iBuf[2] & 0x03) << 6 | o.iBuf[3]
                                    k += 3
                                else:
                                    k += 2
                            else:
                                k += 1
                        else:
                            pass
                    else:
                        pass
                    o.iB = 0
        if o.iB >= 2:
            iOut[k] = (o.iBuf[0] & 255) << 2 | (o.iBuf[1] & 0x30) >> 4
            k += 1
        if o.iB == 3:
            iOut[k] = (o.iBuf[1] & 0x0F) << 4 | (o.iBuf[2] & 0x3C) >> 2
            k += 1
        if self.bToGlue:
            for i in range(k):
                o.iG = iOut[i] & 0xff
                iOut[i] = (iOut[i] ^ o.iDL & 0xff) & 0xff
                o.iDR = self.rotr16(o.iDR, 1) ^ o.iG
                o.iDL = self.rotl16(o.iDL, 1) ^ o.iDR
        iOut[k] = ord('\0')
        return k


