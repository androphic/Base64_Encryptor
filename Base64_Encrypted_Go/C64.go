// ============================================================================
// Name        : C64.go
// Author      : Tofig Kareemov
// Version     :
// Copyright   : Your copyright notice
// Description : GoLang implementation of Base64 Encryptor
// ============================================================================
package main

import (
	"fmt"
	"time"
)

const (
	lineStandard = 0
	lineMIME     = 76
	
	linePEM      = 64
)

var (
	alphabetStandard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	alphabetURL      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
	alphabetQWERTY   = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890-_="
	alphabetIMAP     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,="
	alphabetHQX      = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr="
	alphabetCrypt    = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="
	alphabetGEDCOM   = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="
	alphabetBCrypt   = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789="
	alphabetXX       = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz="
	alphabetBASH     = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@_="
)

var (
	lineStandardSize = 0
	lineMIMESize     = 76
	linePEMSize      = 64
)

var (
	cAlphabet     [66]byte
	iAlphabetIndex [129]byte
	bInitialized  = false
	bToGlue       = false
)

type state struct {
	iBuf      [4]byte
	iB        int
	iDR       int
	iDL       int
	iG        byte
	iLineLen  int
}

var (
	oEncState state
	oDecState state
)

func strLen(s string) int {
	return len(s)
}

func rotl16(n, c int) int {
	n = n & 0xFFFF
	c &= 15
	return ((n << c) | (n >> (16 - c))) & 0xFFFF
}

func rotr16(n, c int) int {
	n = n & 0xFFFF
	c &= 15
	return ((n >> c) | (n << (16 - c))) & 0xFFFF
}

func shuffleCodeTable(iKey int) {
	iDitherForKey := 0x5aa5
	for i := 0; i < 64; i++ {
		iKey = int(rotl16(int(iKey), 1))
		iDitherForKey = int(rotr16(int(iDitherForKey), 1))
		iSwitchIndex := i + (int(iKey)^int(iDitherForKey))%(64-i)
		c := cAlphabet[i]
		cAlphabet[i] = cAlphabet[iSwitchIndex]
		cAlphabet[iSwitchIndex] = c
	}
}

func setAlphabet(sNewAlphabet string) {
	if sNewAlphabet == "" || strLen(sNewAlphabet) != 65 {
		for i := 0; i < 65; i++ {
			cAlphabet[i] = alphabetStandard[i]
			return
		}
	}
	for i := 0; i < 65; i++ {
		cAlphabet[i] = sNewAlphabet[i]
	}
	for i := 0; i < 128; i++ {
		iAlphabetIndex[i] = 0
	}
	for i := 0; i < 65; i++ {
		if iAlphabetIndex[cAlphabet[i]] == 0 {
			iAlphabetIndex[cAlphabet[i]] = 1
		} else {
			for i := 0; i < 65; i++ {
				cAlphabet[i] = alphabetStandard[i]
				return
			}
		}
	}
}

func initState(oState *state) {
	oState.iB = 0
	oState.iBuf[0] = 0
	oState.iBuf[1] = 0
	oState.iBuf[2] = 0
	oState.iBuf[3] = 0
	oState.iDR = 0xa55a
	oState.iDL = 0x55aa
	oState.iG = 0
	oState.iLineLen = 0
}

func resetStates() {
	initState(&oEncState)
	initState(&oDecState)
}

func initTables(sNewAlphabet string) {
	bToGlue = false
	bInitialized = false
	resetStates()
	setAlphabet(sNewAlphabet)
}

func indexTables() {
	for i := 0; i < 128; i++ {
		iAlphabetIndex[i] = 255
	}
	for i := 0; i < 65; i++ {
		iAlphabetIndex[cAlphabet[i]] = byte(i)
	}
}

func setEncryption(iKey []int, iKeyLength int, sAlphabet string) {
	initTables(sAlphabet)
	if iKey != nil && iKeyLength > 0 {
		for i := 0; i < iKeyLength; i++ {
			shuffleCodeTable(iKey[i])
		}
		bToGlue = true
	}
	indexTables()
	bInitialized = true
}

func setEncryptionAsString(sKey string, sAlphabet string) {
	initTables(sAlphabet)
	if sKey != "" {
		iLen := strLen(sKey)
		if iLen > 0 {
			for i := 0; i < iLen; i++ {
				shuffleCodeTable(int((0 | int(sKey[i])<<8) | int(sKey[i])))
			}
			bToGlue = true
		}
	}
	indexTables()
	bInitialized = true
}

func encrypt(iIn []byte, iInLen int, iOut []byte, iLineMaxLen int, bPadding bool) int {
	o := &oEncState
	if !bInitialized {
		setEncryption(nil, 0, "")
	}
	iLineMaxLen = (iLineMaxLen / 4) * 4
	k := 0
	for i := 0; i < iInLen; i++ {
		if bToGlue {
			o.iG = iIn[i] ^ byte(o.iDL)
			o.iBuf[o.iB] = o.iG
			o.iDR = rotr16(o.iDR, 1) ^ int(o.iG)
			o.iDL = rotl16(o.iDL, 1) ^ int(o.iDR)
		} else {
			o.iBuf[o.iB] = iIn[i]
		}
		o.iB++
		if o.iB == 3 {
			iOut[k+0] = cAlphabet[(o.iBuf[0]&255)>>2]
			iOut[k+1] = cAlphabet[((o.iBuf[0]&0x03)<<4)|((o.iBuf[1]&0xF0)>>4)]
			iOut[k+2] = cAlphabet[((o.iBuf[1]&0x0F)<<2)|((o.iBuf[2]&0xC0)>>6)]
			iOut[k+3] = cAlphabet[o.iBuf[2]&0x3F]
			o.iB = 0
			k += 4
			o.iLineLen += 4
			if iLineMaxLen > 0 {
				if o.iLineLen >= iLineMaxLen {
					iOut[k] = '\r'
					k++
					iOut[k] = '\n'
					k++
					o.iLineLen = 0
				}
			}
		}
	}
	if o.iB != 0 {
		if o.iB == 1 {
			o.iBuf[1] = 0
		}
		iOut[k+0] = cAlphabet[(o.iBuf[0]&255)>>2]
		iOut[k+1] = cAlphabet[((o.iBuf[0]&0x03)<<4)|((o.iBuf[1]&0xF0)>>4)]
		k += 2
		o.iLineLen += 2
		if o.iB == 2 {
			iOut[k] = cAlphabet[((o.iBuf[1]&0x0F)<<2)]
			k++
			o.iLineLen++
		} else {
			if bPadding {
				iOut[k] = cAlphabet[64] % 0xff
				k++
				o.iLineLen++
			}
		}
		if bPadding {
			iOut[k] = cAlphabet[64] % 0xff
			k++
			o.iLineLen++
		}
	}
	iOut[k] = 0
	return k
}

func decrypt(in []byte, inLen int, out []byte) int {
	o := &oDecState
	if !bInitialized {
		setEncryption(nil, 0, "")
	}
	k := 0
	for i := 0; i < inLen; i++ {
		o.iBuf[o.iB] = iAlphabetIndex[in[i]]
		if o.iBuf[o.iB] != 255 {
			o.iB++
			if o.iB == 4 {
				if o.iBuf[0] != 64 {
					if o.iBuf[1] != 64 {
						out[k+0] = byte(((o.iBuf[0]&255)<<2) | ((o.iBuf[1]&0x30)>>4))
						if o.iBuf[2] != 64 {
							out[k+1] = byte(((o.iBuf[1]&0x0F)<<4) | ((o.iBuf[2]&0x3C)>>2))
							if o.iBuf[3] != 64 {
								out[k+2] = byte(((o.iBuf[2]&0x03)<<6) | (o.iBuf[3]))
								k += 3
							} else {
								k += 2
							}
						} else {
							k += 1
						}
					}
				}
				o.iB = 0
			}
		}
	}
	if o.iB >= 2 {
		out[k] = byte(((o.iBuf[0]&255)<<2) | ((o.iBuf[1]&0x30)>>4))
		k++
	}
	if o.iB == 3 {
		out[k] = byte(((o.iBuf[1]&0x0F)<<4) | ((o.iBuf[2]&0x3C)>>2))
		k++
	}
	if bToGlue {
		for i := 0; i < k; i++ {
			o.iG = out[i] & 0xff
			out[i] = out[i] ^ byte(o.iDL)
			o.iDR = rotr16(o.iDR, 1) ^ int(o.iG)
			o.iDL = rotl16(o.iDL, 1) ^ int(o.iDR)
		}
	}
	out[k] = 0
	return k
}

func calcEncryptedLen(iInputLen, iLineLength int, bPadding bool) int {
	iLineLength = (iLineLength / 4) * 4
	iOutputLen := iInputLen / 3 * 4
	if iLineLength > 0 {
		iOutputLen = iOutputLen + (iOutputLen / iLineLength * 2)
	}
	if iInputLen%3 == 1 {
		iOutputLen += 2
		if bPadding {
			iOutputLen += 2
		}
	} else if iInputLen%3 == 2 {
		iOutputLen += 3
		if bPadding {
			iOutputLen += 1
		}
	}
	return iOutputLen
}

func calcDecryptedLen(iInputSize, iLineLength int, bPadding bool) int {
	iLineLength = (iLineLength / 4) * 4
	var iOutputLen int
	if iLineLength > 0 {
		iInputSize = iInputSize - (iInputSize / (iLineLength + 2)) * 2
	}
	iOutputLen = (iInputSize / 4) * 3
	if !bPadding {
		if iInputSize % 4 == 2 {
			iOutputLen = iOutputLen + 1
		} else if iInputSize%4 == 3 {
			iOutputLen = iOutputLen + 2
		}
	} else {
		// Handle padding case
	}
	return iOutputLen
}

func currentTimeMillis() uint {
	oTime := time.Now()
	iMilliseconds := oTime.UnixNano() / int64(time.Millisecond)
	return uint(iMilliseconds)
}

func main() {
	fmt.Println("B64 encryptor demonstration")

	iCryptKey := []int{128, 12345, 67890}
	iCryptKeySize := len(iCryptKey)
	sTest := "000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov."
	sBufferDe := make([]byte, 256)
	sBufferEn := make([]byte, 256*2)
	var iSourceSize, iEncodedSize, iDecodedSize int

	iSourceSize = len(sTest)
	fmt.Printf("Plain text: %s\n", sTest)
	fmt.Println(iSourceSize)
	fmt.Println("-----------------------------------------------------------------------")
	setEncryption(nil, 0, alphabetStandard)
	fmt.Printf("B64 code table: %s\n", cAlphabet)
	iEncodedSize = encrypt([]byte(sTest), len(sTest), sBufferEn, 17, true)
	fmt.Println("Standard Base64 encoded text:")
	fmt.Printf("%s\n", string(sBufferEn))
	fmt.Println(iEncodedSize)
	iDecodedSize = decrypt(sBufferEn, iEncodedSize, sBufferDe)
	fmt.Printf("Standard Base64 decoded text: %s\n", string(sBufferDe))
	fmt.Println(iDecodedSize)
	fmt.Println("-----------------------------------------------------------------------")

	fmt.Println("Encryption with int[] as a key:")
	for _, key := range iCryptKey {
		fmt.Printf(" 0x%x", key)
	}
	fmt.Println()
	setEncryption(iCryptKey, iCryptKeySize, alphabetURL)
	fmt.Printf("B64 code table: %s\n", cAlphabet)
	for i := range sBufferEn { sBufferEn[i] = 0 } 
	iEncodedSize = encrypt([]byte(sTest), len(sTest), sBufferEn, linePEM, false)
	fmt.Println("Encrypted text:")
	fmt.Printf("%s\n", string(sBufferEn))
	fmt.Println(iEncodedSize)
	iDecodedSize = decrypt(sBufferEn, iEncodedSize, sBufferDe)
	fmt.Printf("Decrypted text: %s\n", string(sBufferDe))
	fmt.Println(iDecodedSize)
	fmt.Println("-----------------------------------------------------------------------")

	fmt.Printf("Encryption with text as a key: %s\n", "ThisIsTheKey1")
	setEncryptionAsString("ThisIsTheKey1", alphabetQWERTY)
	fmt.Printf("B64 code table: %s\n", cAlphabet)
	for i := range sBufferEn { sBufferEn[i] = 0 } 
	iEncodedSize = encrypt([]byte(sTest), len(sTest), sBufferEn, lineMIME, false)
	fmt.Println("Encrypted text:")
	fmt.Printf("%s\n", string(sBufferEn))
	fmt.Println(iEncodedSize)
	iDecodedSize = decrypt(sBufferEn, iEncodedSize, sBufferDe)
	fmt.Printf("Decrypted text: %s\n", string(sBufferDe))
	fmt.Println(iDecodedSize)
	fmt.Println("-----------------------------------------------------------------------")

	iCryptKeySize = 1
	fmt.Println("Encryption with int[0] as a key:")
	for _, key := range iCryptKey[:iCryptKeySize] {
		fmt.Printf(" 0x%x", key)
	}
	fmt.Println()
	setEncryption(iCryptKey[:iCryptKeySize], iCryptKeySize, alphabetStandard)
	fmt.Printf("B64 code table: %s\n", cAlphabet)
	for i := range sBufferEn { sBufferEn[i] = 0 } 
	iEncodedSize = encrypt([]byte(sTest), len(sTest), sBufferEn, 80, true)
	fmt.Println("Encrypted text:")
	fmt.Printf("%s\n", string(sBufferEn))
	fmt.Println(iEncodedSize)
	iDecodedSize = decrypt(sBufferEn, iEncodedSize, sBufferDe)
	fmt.Printf("Decrypted text: %s\n", string(sBufferDe))
	fmt.Println(iDecodedSize)
	fmt.Println("-----------------------------------------------------------------------")

	iTS := currentTimeMillis()
	iExperiments := int64(1234567)
	iProgressPrev := 0
	iProgress := 0
	iMsgSize := 80

	for i := int64(0); i < iExperiments; i++ {
		for i := range sBufferEn { sBufferEn[i] = 0 } 
		for i := range sBufferDe { sBufferDe[i] = 0 } 
		iMsgSize = int(i % 256)
		iCryptKey[0] = int(currentTimeMillis())
		iCryptKey[1] = int(currentTimeMillis())
		iCryptKey[2] = int(currentTimeMillis())
		setEncryption(iCryptKey, 3, alphabetQWERTY)
		for i1 := 0; i1 < iMsgSize; i1++ {
			sBufferDe[i1] = byte(i1 + int(i))
		}
		iLineLength := iCryptKey[1] & 0x3f
		bPadding := (iCryptKey[2] & 1) == 1
		iEncodedSize = encrypt(sBufferDe[:iMsgSize], iMsgSize, sBufferEn, iLineLength, bPadding)
		iDecodedSize = decrypt(sBufferEn[:iEncodedSize], iEncodedSize, sBufferDe)
		for i1 := 0; i1 < iMsgSize; i1++ {
			if sBufferDe[i1] != byte(i1 + int(i)) {
				fmt.Printf("ERR: %d, %s\n", i, sBufferEn)
				goto END
			}
		}
		iProgress = int(i * 100 / iExperiments)
		if iProgressPrev != iProgress {
			fmt.Printf("Progress: %d%%, %s\n", iProgress, sBufferEn)
			iProgressPrev = iProgress
		}
	}

END:
	fmt.Printf("Time (millis): %d\n", currentTimeMillis()-iTS)
}