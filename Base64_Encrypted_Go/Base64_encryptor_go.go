// ============================================================================
// Name        : Base64_Encrypted_go.go
// Author      : Tofig Kareemov
// Version     :
// Copyright   : Your copyright notice
// Description : GoLang implementation of Base64 Encryptor
// ============================================================================
package main

import (
	"fmt"
	"time"
	"math/rand"
)

type B64Encryptor struct {
	b64Code      [65]byte
	b64Index     [65]byte
	bB64Initialized bool
	bB64ToGlue bool
}

func (b *B64Encryptor) mb64Int(ch byte) byte {
	switch ch {
	case 61:
		return 64
	case 43:
		return 62
	case 47:
		return 63
	case 48, 49, 50, 51, 52, 53, 54, 55, 56, 57:
		return byte(ch) + 4
	case 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90:
		return byte(ch - 'A')
	case 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122:
		return byte(ch-'a') + 26
	}
	return 255
}

func (b *B64Encryptor) mb64Rotl16(n int, c int) int {
	n &= 0xFFFF
	c &= 15
	return ((n << c) | (n >> (16 - c))) & 0xFFFF
}

func (b *B64Encryptor) mb64Rotr16(n int, c int) int {
	n &= 0xFFFF
	c &= 15
	return ((n >> c) | (n << (16 - c))) & 0xFFFF
}

func (b *B64Encryptor) mB64IntFromIndex(ch byte) byte {
	var iCh = b.mb64Int(byte(ch))
	if iCh == 255 {
		return 255
	}
	if ch == 61 {
		return 64
	}
	return b.b64Index[b.mb64Int(byte(ch))]
}

func (b *B64Encryptor) mb64Shuffle(iKey int) {
	iDither := 0x5aa5
	for i := 0; i < 64; i++ {
		iKey = b.mb64Rotl16(iKey, 1)
		iDither = b.mb64Rotr16(iDither, 1)
		iSwitchIndex := i + (iKey^iDither)%(64-i)
		iA := b.b64Code[i]
		b.b64Code[i] = b.b64Code[iSwitchIndex]
		b.b64Code[iSwitchIndex] = iA
	}
}

func (b64 *B64Encryptor) mb64InitTables() {
	sB64Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b64.bB64ToGlue = false
	b64.bB64Initialized = false
	for i := 0; i < 64; i++ {
		b64.b64Index[i] = (byte)(i & 0xff)
		b64.b64Code[i] = sB64Chars[i]
	}
	b64.b64Code[64] = 0
}

func (b64 *B64Encryptor) mB64IndexTables() {
	for i := 0; i < 64; i++ {
		b64.b64Index[b64.mb64Int(b64.b64Code[i])] = byte(i)
	}
}

func (b64 *B64Encryptor) b64SetKeyI(iKey []int, iSize int) {
	b64.mb64InitTables()
	if iKey != nil {
		for i := 0; i < iSize; i++ {
			b64.mb64Shuffle(iKey[i])
		}
		b64.mB64IndexTables()
		b64.bB64ToGlue = true
	}
	b64.bB64Initialized = true
}

func (b64 *B64Encryptor) b64SetKeyS(sKey string) {
	b64.mb64InitTables()
	if sKey != "" {
		for i := 0; i < len(sKey); i++ {
			b64.mb64Shuffle(0 | int(sKey[i]) | (int(sKey[i]) << 8))
		}
		b64.mB64IndexTables()
		b64.bB64ToGlue = true
	}
	b64.bB64Initialized = true
}


func (b *B64Encryptor) b64eSize(inSize int) int {
	return ((inSize-1)/3)*4 + 4
}

func (b *B64Encryptor) b64dSize(inSize int) int {
	return ((3 * inSize) / 4)
}

func (b *B64Encryptor) b64Encode(input []byte, iLen int, output []byte, iTextLineLength int) int {
	if !b.bB64Initialized {
		b.b64SetKeyI(nil, 0)
	}
	i, j, k := 0, 0, 0
	s := [3]int{}
	iDitherR := 0xa55a
	iDitherL := 0x55aa
	iG := 0
	iTextLineCount := 0

    iTextLineLength = iTextLineLength / 4 * 4
	for i < iLen {
		if (b.bB64ToGlue) {
			iG = (((int(input[i]) ^ iDitherL) & 0xff) & 0xff)
			s[j] = iG
			iDitherR = b.mb64Rotr16(iDitherR, 1) ^ iG
			iDitherL = b.mb64Rotl16(iDitherL, 1) ^ iDitherR
			} else {
				s[j] = int(input[i])
			}
		j++
		if j == 3 {
			output[k+0] = b.b64Code[(s[0]&255)>>2]
			output[k+1] = b.b64Code[((s[0]&0x03)<<4)|((s[1]&0xF0)>>4)]
			output[k+2] = b.b64Code[((s[1]&0x0F)<<2)|((s[2]&0xC0)>>6)]
			output[k+3] = b.b64Code[s[2]&0x3F]
			j = 0
			k += 4
            if iTextLineLength > 0 {
				iTextLineCount += 4
				if iTextLineCount >= iTextLineLength {
					output[k] = '\n'
					k += 1
					iTextLineCount = 0
				}
			}
		}
		i++
	}
	if j != 0 {
		if j == 1 {
			s[1] = 0
		}
		output[k+0] = b.b64Code[(s[0]&255)>>2]
		output[k+1] = b.b64Code[((s[0]&0x03)<<4)|((s[1]&0xF0)>>4)]
		if j == 2 {
			output[k+2] = b.b64Code[((s[1] & 0x0F) << 2)]
		} else {
			output[k+2] = '='
		}
		output[k+3] = '='
		k += 4
		if iTextLineLength > 0 {
			iTextLineCount += 4
			if iTextLineCount >= iTextLineLength {
				output[k] = '\n'
				k += 1
				iTextLineCount = 0
			}
		}
	}
	output[k] = 0
	return k
}

func (b *B64Encryptor) b64Decode(input []byte, iLen int, output []byte) int {
	if !b.bB64Initialized {
		b.b64SetKeyI(nil, 0)
	}
	j, k := 0, 0
	s := [4]byte{}
	iDitherR := 0xa55a
	iDitherL := 0x55aa
	iG := byte(0)

	for i := 0; i < iLen; i++ {
		s[j] = b.mB64IntFromIndex(input[i])
		if s[j] != 255 {
			j++
			if j == 4 {
				if s[1] != 64 {
					output[k+0] = (byte(((s[0] & 255) << 2) | ((s[1] & 0x30) >> 4)))
					if s[2] != 64 {
						output[k+1] = (byte(((s[1] & 0x0F) << 4) | ((s[2] & 0x3C) >> 2)))
						if s[3] != 64 {
							output[k+2] = (byte(((s[2] & 0x03) << 6) | s[3]))
							k += 3
						} else {
							k += 2
						}
					} else {
						k += 1
					}
				}
				j = 0
			}
		}
	}
	if b.bB64ToGlue {
		i := 0
		for i < k {
			iG = output[i]
			output[i] = output[i] ^ byte(iDitherL)
			iDitherR = b.mb64Rotr16(iDitherR, 1) ^ int(iG)
			iDitherL = b.mb64Rotl16(iDitherL, 1) ^ iDitherR
			i++
		}
	}
	output[k] = 0
	return k
}

func main() {
	var o B64Encryptor 
	fmt.Println("B64 encryptor demonstration")

	for i := 0; i < 32; i++ {
		fmt.Printf(" %d, ", o.mb64Rotl16(0xa5, i))
	}
	fmt.Println()

	for i := 0; i < 32; i++ {
		fmt.Printf(" %d, ", o.mb64Rotr16(0xa5, i))
	}
	fmt.Println()

	sTest := []byte("000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.")
	sBufferDe := make([]byte, 256)
	sBufferEn := make([]byte, 256*4/3+1)
	iSourceSize := len(sTest)
	iEncodedSize := 0
	iDecodedSize := 0
	iCryptKey := []int{128, 12345, 67890}

	fmt.Println("Plain text:", string(sTest))
	fmt.Println(iSourceSize)
	fmt.Println("-----------------------------------------------------------------------")
	fmt.Println("Standard Base64 encoding")
	o.b64SetKeyI(nil, 0)
	fmt.Println("B64 code table: ", fmt.Sprintf("%s",o.b64Code))
	fmt.Println("B64 code index table: ", o.b64Index)
	iEncodedSize = o.b64Encode(sTest, len(sTest), sBufferEn, 16)
	fmt.Println("Standard Base64 encoded text:")
	fmt.Println(string(sBufferEn))
	fmt.Println(iEncodedSize)
	iDecodedSize = o.b64Decode(sBufferEn, iEncodedSize, sBufferDe)
	fmt.Println("Standard Base64 decoded text:")
	fmt.Println(string(sBufferDe))
	fmt.Println(iDecodedSize)
	fmt.Println("-----------------------------------------------------------------------")

	sBufferDe = make([]byte, 256)
	sBufferEn = make([]byte, 256*4/3+1)
	fmt.Println("Encryption with int[] as key: ", iCryptKey)
	o.b64SetKeyI(iCryptKey, len(iCryptKey))
	fmt.Println("B64 code table: ", fmt.Sprintf("%s",o.b64Code))
	fmt.Println("B64 code index table: ", o.b64Index)
	iEncodedSize = o.b64Encode(sTest, len(sTest), sBufferEn, 32)
	fmt.Println("Encrypted text:")
	fmt.Println(string(sBufferEn))
	fmt.Println(iEncodedSize)
	iDecodedSize = o.b64Decode(sBufferEn, iEncodedSize, sBufferDe)
	fmt.Println("Decrypted text:")
	fmt.Println(string(sBufferDe))
	fmt.Println(iDecodedSize)
	fmt.Println("-----------------------------------------------------------------------")

	sBufferDe = make([]byte, 256)
	sBufferEn = make([]byte, 256*4/3+1)
	fmt.Println("Encryption with String as key: ", "ThisIsTheKey1")
	o.b64SetKeyS("ThisIsTheKey1")
	fmt.Println("B64 code table: ", fmt.Sprintf("%s",o.b64Code))
	fmt.Println("B64 code index table: ", o.b64Index)
	iEncodedSize = o.b64Encode(sTest, len(sTest), sBufferEn, 64)
	fmt.Println("Encrypted text:")
	fmt.Println(string(sBufferEn))
	fmt.Println(iEncodedSize)
	iDecodedSize = o.b64Decode(sBufferEn, iEncodedSize, sBufferDe)
	fmt.Println("Decrypted text:")
	fmt.Println(string(sBufferDe))
	fmt.Println(iDecodedSize)
	fmt.Println("-----------------------------------------------------------------------")

	sBufferDe = make([]byte, 256)
	sBufferEn = make([]byte, 256*4/3+1)
	fmt.Println("Encryption with int[0] as key: ", iCryptKey[0])
	o.b64SetKeyI(iCryptKey, 1)
	fmt.Println("B64 code table: ", fmt.Sprintf("%s",o.b64Code))
	fmt.Println("B64 code index table: ", o.b64Index)
	iEncodedSize = o.b64Encode(sTest, len(sTest), sBufferEn, 80)
	fmt.Println("Encrypted text:")
	fmt.Println(string(sBufferEn))
	fmt.Println(iEncodedSize)
	iDecodedSize = o.b64Decode(sBufferEn, iEncodedSize, sBufferDe)
	fmt.Println("Decrypted text:")
	fmt.Println(string(sBufferDe))
	fmt.Println(iDecodedSize)
	fmt.Println("-----------------------------------------------------------------------")

	sBufferDe = make([]byte, 256)
	sBufferEn = make([]byte, 256*4/3+1)
	iTS := time.Now().UnixNano() / int64(time.Millisecond)
	iExperiments := int64(1234567)
	iProgressPrev := 0
	iProgress := 0
	iMsgSize := 80

	for i := int64(0); i < iExperiments; i++ {
		sBufferDe = make([]byte, 256)
		sBufferEn = make([]byte, 256*4/3+1)
		iMsgSize = int(i % 256)
		iCryptKey[0] = rand.Intn(1000000) // use a random number instead of System.currentTimeMillis()
		iCryptKey[1] = rand.Intn(1000000)
		iCryptKey[2] = rand.Intn(1000000)
		o.b64SetKeyI(iCryptKey, 3)

		for i1 := 0; i1 < iMsgSize; i1++ {
			sBufferDe[i1] = byte(i1 + int(i))
		}

		iEncodedSize = o.b64Encode(sBufferDe, iMsgSize, sBufferEn, 0)
		iDecodedSize = o.b64Decode(sBufferEn, iEncodedSize, sBufferDe)

		for i1 := 0; i1 < iMsgSize; i1++ {
			if sBufferDe[i1] != byte(i1+int(i)) {
				fmt.Println("ERR:", i, string(sBufferEn))
				return
			}
		}

		iProgress = int(i * 100 / iExperiments)
		if iProgressPrev != iProgress {
			fmt.Println("Progress:", iProgress, "%,", string(sBufferEn))
			iProgressPrev = iProgress
		}
	}

	fmt.Println("Time (millis):", int(time.Now().UnixNano()/int64(time.Millisecond))-int(iTS))
}
