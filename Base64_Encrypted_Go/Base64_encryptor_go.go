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
)

type B64Encryptor struct {
	b64Code      [65]byte
	b64Index     [65]byte
	bInitialized bool
}

func (b *B64Encryptor) b64Int(ch byte) byte {
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
	return 64
}

func (b *B64Encryptor) rotl16(n int, c int) int {
	n &= 0xFFFF
	c &= 15
	return ((n << c) | (n >> (16 - c))) & 0xFFFF
}

func (b *B64Encryptor) rotr16(n int, c int) int {
	n &= 0xFFFF
	c &= 15
	return ((n >> c) | (n << (16 - c))) & 0xFFFF
}

func (b *B64Encryptor) b64IntFromIndex(ch byte) byte {
	if ch == 61 {
		return 64
	}
	return b.b64Index[b.b64Int(byte(ch))]
}

func (b *B64Encryptor) b64Shuffle(iKey int) {
	iDither := 0x5aa5
	for i := 0; i < 64; i++ {
		iKey = b.rotl16(iKey, 1)
		iDither = b.rotr16(iDither, 1)
		iSwitchIndex := i + (iKey^iDither)%(64-i)
		iA := b.b64Code[i]
		b.b64Code[i] = b.b64Code[iSwitchIndex]
		b.b64Code[iSwitchIndex] = iA
	}
	for i := 0; i < 64; i++ {
		b.b64Index[b.b64Int(b.b64Code[i])] = byte(i)
	}
}

func (b *B64Encryptor) b64Init(iKey int) {
	sB64Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i := 0; i < 64; i++ {
		b.b64Index[i] = (byte)(i & 0xff)
		b.b64Code[i] = sB64Chars[i]
	}
	b.b64Shuffle(iKey)
	b.bInitialized = true
}

func (b *B64Encryptor) b64eSize(inSize int) int {
	return ((inSize-1)/3)*4 + 4
}

func (b *B64Encryptor) b64dSize(inSize int) int {
	return ((3 * inSize) / 4)
}

func (b *B64Encryptor) b64Encode(input []byte, iLen int, output []byte) int {
	if !b.bInitialized {
		b.b64Init(0)
	}
	i, j, k := 0, 0, 0
	s := [3]int{}
	iDither := 0xa55a
	iG := 0

	for i < iLen {
		iG = (((int(input[i]) ^ iDither) & 0xff) & 0xff)
		s[j] = iG
		j++
		iDither = b.rotr16(iDither, 1) ^ iG
		if j == 3 {
			output[k+0] = b.b64Code[(s[0]&255)>>2]
			output[k+1] = b.b64Code[((s[0]&0x03)<<4)+((s[1]&0xF0)>>4)]
			output[k+2] = b.b64Code[((s[1]&0x0F)<<2)+((s[2]&0xC0)>>6)]
			output[k+3] = b.b64Code[s[2]&0x3F]
			j = 0
			k += 4
		}
		i++
	}
	if j != 0 {
		if j == 1 {
			s[1] = 0
		}
		output[k+0] = b.b64Code[(s[0]&255)>>2]
		output[k+1] = b.b64Code[((s[0]&0x03)<<4)+((s[1]&0xF0)>>4)]
		if j == 2 {
			output[k+2] = b.b64Code[((s[1] & 0x0F) << 2)]
		} else {
			output[k+2] = '='
		}
		output[k+3] = '='
		k += 4
	}
	return k
}

func (b *B64Encryptor) b64Decode(input []byte, iLen int, output []byte) int {
	if !b.bInitialized {
		b.b64Init(0)
	}
	j, k := 0, 0
	s := [4]byte{}
	iDither := 0xa55a
	iG := byte(0)

	for i := 0; i < iLen; i++ {
		s[j] = b.b64IntFromIndex(input[i])
		j++
		if j == 4 {
			if s[1] != 64 {
				output[k+0] = (byte(((s[0] & 255) << 2) + ((s[1] & 0x30) >> 4)))
				if s[2] != 64 {
					output[k+1] = (byte(((s[1] & 0x0F) << 4) + ((s[2] & 0x3C) >> 2)))
					if s[3] != 64 {
						output[k+2] = (byte(((s[2] & 0x03) << 6) + s[3]))
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
	i := 0
	for i < k {
		iG = output[i]
		output[i] = output[i] ^ byte(iDither)
		iDither = b.rotr16(iDither, 1) ^ int(iG)
		i++
	}
	return k
}

func main() {
	iBufferDe := [256]byte{}
	iBufferEn := [256 * 4 / 3]byte{}

	fmt.Println("B64 encryptor demonstration")
	iCryptKey := 128

	var b64Encryptor B64Encryptor
	b64Encryptor.b64Init(iCryptKey)

	fmt.Printf("Crypt key: 0x%x\n", iCryptKey)
	fmt.Printf("B64 code table: %s\n", b64Encryptor.b64Code)

	sTest := "000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov."
	fmt.Printf("Plain text: %s\n", sTest)

	iSourceSize := len(sTest)
	fmt.Printf("%d\n", iSourceSize)

	for i := 0; i < len(sTest); i++ {
		iBufferDe[i] = sTest[i]
	}
	iBufferEnLen := b64Encryptor.b64Encode(iBufferDe[:], len(sTest), iBufferEn[:])
	fmt.Printf("Crypt text: %s\n", iBufferEn)
	fmt.Printf("%d\n", iBufferEnLen)

	iBufferDeLen := b64Encryptor.b64Decode(iBufferEn[:], iBufferEnLen, iBufferDe[:])
	fmt.Printf("Decrypt text: %s\n", iBufferDe)
	fmt.Printf("%d\n", iBufferDeLen)

	iTS := int(time.Now().Unix())
	iExperiments := int64(12345678)
	iProgressPrev := 0
	iProgress := 0
	iMsgSize := 80

	for i := int64(0); i < iExperiments; i++ {
		iBufferDe = [256]byte{}
		iBufferEn = [256 * 4 / 3]byte{}
		iMsgSize = int(i % 256)
		iCryptKey = int(time.Now().Unix())
		b64Encryptor.b64Init(iCryptKey)
		for i1 := 0; i1 < iMsgSize; i1++ {
			iBufferDe[i1] = byte(i1 + int(i))
		}
		iBufferEnLen = b64Encryptor.b64Encode(iBufferDe[:], iMsgSize, iBufferEn[:])
		iBufferDeLen = b64Encryptor.b64Decode(iBufferEn[:], iBufferEnLen, iBufferDe[:])
		for i1 := 0; i1 < iMsgSize; i1++ {
			if iBufferDe[i1] != byte(i1+int(i)) {
				fmt.Printf("ERR: %d, %s\n", i, iBufferEn)
				return
			}
		}

		iProgress = int(i * 100 / iExperiments)
		if iProgressPrev != iProgress {
			fmt.Printf("Progress: %d%%, %s\n", iProgress, iBufferEn)
			iProgressPrev = iProgress
		}
	}

	fmt.Printf("Time (seconds): %d\n", int(time.Now().Unix())-iTS)
}
