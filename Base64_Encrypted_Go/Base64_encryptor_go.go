//============================================================================
// Name        : Base64_Encrypted_go.go
// Author      : Tofig Kareemov
// Version     :
// Copyright   : Your copyright notice
// Description : GoLang implementation of Base64 Encryptor
//============================================================================

package main

import (
	"fmt"
	"strings"
	"time"
)

type B64Encryptor struct {
	b64Code      string
	b64Index     [65]int
	bInitialized bool
}

func (b *B64Encryptor) b64Int(ch byte) int {
	switch ch {
	case 61:
		return 64
	case 43:
		return 62
	case 47:
		return 63
	case 48, 49, 50, 51, 52, 53, 54, 55, 56, 57:
		return int(ch) + 4
	case 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90:
		return int(ch - 'A')
	case 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122:
		return int(ch-'a') + 26
	}
	return -1
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

func (b *B64Encryptor) b64IntFromIndex(ch int) int {
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
		iSwitchIndex := i + (iKey ^ iDither)%(64-i)
		iA := b.b64Code[i]
		b.b64Code = b.b64Code[:i] + string(b.b64Code[iSwitchIndex]) + b.b64Code[i+1:]
		b.b64Code = b.b64Code[:iSwitchIndex] + string(iA) + b.b64Code[iSwitchIndex+1:]
	}
	for i := 0; i < 64; i++ {
		b.b64Index[b.b64Int(b.b64Code[i])] = i
	}
}

func (b *B64Encryptor) b64Init(iKey int) {
	sB64Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b.b64Code = ""
	for i := 0; i < 64; i++ {
		b.b64Index[i] = i & 0xff
		b.b64Code += string(sB64Chars[i])
	}
	//b.b64Code += string(0)
	b.b64Shuffle(iKey)
	b.bInitialized = true
}

func (b *B64Encryptor) b64eSize(inSize int) int {
	return ((inSize - 1) / 3) * 4 + 4
}

func (b *B64Encryptor) b64dSize(inSize int) int {
	return ((3 * inSize) / 4)
}

func (b *B64Encryptor) b64Encode(input string) string {
	if !b.bInitialized {
		b.b64Init(0)
	}
	var output strings.Builder
	i, j, k := 0, 0, 0
	s := [3]int{}
	iDither := 0xa55a
	iG := 0

	for i < len(input) {
		iG = (((int(input[i]) ^ iDither) & 0xff) & 0xff)
		s[j] = iG
		j++
		iDither = b.rotr16(iDither, 1) ^ iG

		if j == 3 {
			output.WriteByte(b.b64Code[(s[0]&255)>>2])
			output.WriteByte(b.b64Code[((s[0]&0x03)<<4)+((s[1]&0xF0)>>4)])
			output.WriteByte(b.b64Code[((s[1]&0x0F)<<2)+((s[2]&0xC0)>>6)])
			output.WriteByte(b.b64Code[s[2]&0x3F])
			j = 0
			k += 4
		}
		i++
	}
	if j != 0 {
		if j == 1 {
			s[1] = 0
		}
		output.WriteByte(b.b64Code[(s[0]&255)>>2])
		output.WriteByte(b.b64Code[((s[0]&0x03)<<4)+((s[1]&0xF0)>>4)])
		if j == 2 {
			output.WriteByte(b.b64Code[((s[1]&0x0F)<<2)])
		} else {
			output.WriteByte('=')
		}
		output.WriteByte('=')
		k += 4
	}
	return output.String()
}

func (b *B64Encryptor) b64Decode(input string) string {
	if !b.bInitialized {
		b.b64Init(0)
	}
	var output strings.Builder
	var output_glued strings.Builder
	j, k := 0, 0
	s := [4]int{}
	iDither := 0xa55a
	iG := 0

	for i := 0; i < len(input); i++ {
		s[j] = b.b64IntFromIndex(int(input[i]))
		j++
		if j == 4 {
			if s[1] != 64 {
				output.WriteByte(byte(((s[0]&255)<<2)+((s[1]&0x30)>>4)))
				if s[2] != 64 {
					output.WriteByte(byte(((s[1]&0x0F)<<4)+((s[2]&0x3C)>>2)))
					if s[3] != 64 {
						output.WriteByte(byte(((s[2]&0x03)<<6) + s[3]))
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
		iG = int(output.String()[i]) & 0xff
		char := output.String()[i]
		output_glued.WriteByte(byte(char^(byte)(iDither & 0xff)) & 0xff)
		iDither = b.rotr16(iDither, 1) ^ iG
		i++
	}
	output = output_glued

	return output.String()
}

func main() {
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

	sBufferEn := b64Encryptor.b64Encode(sTest)
	fmt.Printf("Crypt text: %s\n", sBufferEn)
	fmt.Printf("%d\n", len(sBufferEn))

	sBufferDe := b64Encryptor.b64Decode(sBufferEn)
	fmt.Printf("Decrypt text: %s\n", sBufferDe)
	fmt.Printf("%d\n", len(sBufferDe))

	iTS := int(time.Now().Unix())
	iExperiments := int64(1234567)
	iProgressPrev := 0
	iProgress := 0
	iMsgSize := 80

	for i := int64(0); i < iExperiments; i++ {
		iMsgSize = int(i % 256)
		iCryptKey = int(time.Now().Unix())
		b64Encryptor.b64Init(iCryptKey)
		var myStringBuilder strings.Builder
		for i1 := 0; i1 < iMsgSize; i1++ {
			myStringBuilder.WriteByte((byte)((i1 + int(i)) & 0xff))
		}
		sBufferDe = myStringBuilder.String()

		sBufferEn = b64Encryptor.b64Encode(string(sBufferDe))
		sBufferDe = b64Encryptor.b64Decode(sBufferEn)

		for i1 := 0; i1 < iMsgSize; i1++ {
			if sBufferDe[i1] != byte(i1+int(i)) {
				fmt.Printf("ERR: %d, %s\n", i, sBufferEn)
				return
			}
		}

		iProgress = int(i * 100 / iExperiments)
		if iProgressPrev != iProgress {
			fmt.Printf("Progress: %d%%, %s\n", iProgress, sBufferEn)
			iProgressPrev = iProgress
		}
	}

	fmt.Printf("Time (millis): %d\n", int(time.Now().Unix())-iTS)
}

