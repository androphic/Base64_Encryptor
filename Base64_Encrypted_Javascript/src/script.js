class B64Encryptor {
  static iB64Code = new Array(65);
  static iB64Index = new Array(65);
  static bB64Initialized = false;
  static bB64ToGlue = false;

  static b64_int(chr) {
    let ch = ("" + chr).charCodeAt(0);
    if (ch == 61) {
      return 64;
    } else if (ch == 43) {
      return 62;
    } else if (ch == 47) {
      return 63;
    } else if (ch > 47 && ch < 58) {
      return ch + 4; // numbers
    } else if (ch > 64 && ch < 91) {
      return ch - 65; // capitals
    } else if (ch > 96 && ch < 123) {
      return ch - 97 + 26; // small letters
    } else {
      return 255;
    }
  }

  static mb64_rotl16(n, c) {
    n = n & 0xffff;
    c &= 15;
    return ((n << c) | (n >> (16 - c))) & 0xffff;
  }

  static mb64_rotr16(n, c) {
    n = n & 0xffff;
    c &= 15;
    return ((n >> c) | (n << (16 - c))) & 0xffff;
  }

  static b64_int_from_index(ch) {
    let iCh = this.b64_int(ch);
    if (iCh == 255) {
      return 255;
    }
    if (ch == '=') {
      return 64;
    } else {
      return this.iB64Index[iCh];
    }
  }

  static b64_shuffle(iKey) {
    let iDither = 0x5aa5;
    for (let i = 0; i < 64; ++i) {
      iKey = this.mb64_rotl16(iKey, 1);
      iDither = this.mb64_rotr16(iDither, 1);
      let iSwitchIndex = i + ((iKey ^ iDither) % (64 - i));
      let iA = this.iB64Code[i];
      this.iB64Code[i] = this.iB64Code[iSwitchIndex];
      this.iB64Code[iSwitchIndex] = iA;
    }
  }

  static iB64Index_tables() {
    for (let i = 0; i < 64; ++i) {
      this.iB64Index[this.b64_int(this.iB64Code[i])] = i;
    }
  }

  static b64_init_tables() {
    let sB64Chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    this.bB64ToGlue = false;
    this.bInitialized = false;
    for (let i = 0; i < 64; ++i) {
      this.iB64Index[i] = i & 0xff;
      this.iB64Code[i] = sB64Chars[i];
    }
    this.iB64Code[64] = 0;
  }

  static b64_set_key_i(iKey, iSize) {
    this.b64_init_tables();
    if (iKey != null) {
      let i = 0;
      for (i = 0; i < iSize; ++i) {
        this.b64_shuffle(iKey[i]);
      }
      this.iB64Index_tables();
      this.bB64ToGlue = true;
    }
    this.bInitialized = true;
  }

  static b64_set_key_s(sKey) {
    this.b64_init_tables();
    if (sKey != "") {
      let i = 0;
      for (i = 0; i < sKey.length; ++i) {
        this.b64_shuffle(0x0000 | sKey.charCodeAt(i) | (sKey.charCodeAt(i) << 8));
      }
      this.iB64Index_tables();
      this.bB64ToGlue = true;
    }
    this.bInitialized = true;
  }

  static b64e_size(in_size) {
    return ((in_size - 1) / 3) * 4 + 4;
  }

  static b64d_size(in_size) {
    return (3 * in_size) / 4;
  }

  static b64_encode(inArr, in_len, outArr, textLineLength) {
    if (!this.bInitialized) {
      this.b64_set_key_i(null, 0);
    }
    let i = 0,
      j = 0,
      k = 0;
    let s = new Array(3);
    let iDitherR = 0xa55a;
    let iDitherL = 0x55aa;
    let iG = 0;
    let textLineCount = 0;

    textLineLength = textLineLength / 4 * 4;
    for (i = 0; i < in_len; i++) {
      if (this.bB64ToGlue) {
        iG = (inArr[i] ^ iDitherL & 0xff) & 0xff;
        s[j] = iG;
        iDitherR = this.mb64_rotr16(iDitherR, 1) ^ iG;
        iDitherL = this.mb64_rotl16(iDitherL, 1) ^ iDitherR;
      } else {
        s[j] = inArr[i];
      }
      ++j;
      if (j == 3) {
        outArr[k + 0] = this.iB64Code[(s[0] & 255) >> 2];
        outArr[k + 1] =
          this.iB64Code[((s[0] & 0x03) << 4) | ((s[1] & 0xf0) >> 4)];
        outArr[k + 2] =
          this.iB64Code[((s[1] & 0x0f) << 2) | ((s[2] & 0xc0) >> 6)];
        outArr[k + 3] = this.iB64Code[s[2] & 0x3f];
        j = 0;
        k += 4;
        if (textLineLength > 0) {
					textLineCount += 4;
					if (textLineCount >= textLineLength) {
						outArr[k] = '\n';
						++k;
						textLineCount = 0;
					}
				}
      }
    }
    if (j != 0) {
      if (j == 1) {
        s[1] = 0;
      }
      outArr[k + 0] = this.iB64Code[(s[0] & 255) >> 2];
      outArr[k + 1] =
        this.iB64Code[((s[0] & 0x03) << 4) | ((s[1] & 0xf0) >> 4)];
      if (j === 2) {
        outArr[k + 2] = this.iB64Code[(s[1] & 0x0f) << 2];
      } else {
        outArr[k + 2] = '=';
      }
      outArr[k + 3] = '=';
      k += 4;
      if (textLineLength > 0) {
        textLineCount += 4;
        if (textLineCount >= textLineLength) {
          outArr[k] = '\n';
          ++k;
          textLineCount = 0;
        }
      }
  }
    outArr[k] = '\0';
    return k;
  }

  static b64_decode(inArr, in_len, outArr) {
    if (!this.bInitialized) {
      this.b64_set_key_i(null, 0);
    }
    let j = 0, k = 0;
    let s = new Array(4);
    let iDitherR = 0xa55a;
    let iDitherL = 0x55aa;
    let iG = 0;
    for (let i = 0; i < in_len; i++) {
      s[j] = this.b64_int_from_index(inArr[i]);
      if (s[j] != 255) {
        ++j;
        if (j == 4) {
          if (s[1] != 64) {
            outArr[k + 0] = ((s[0] & 255) << 2) | ((s[1] & 0x30) >> 4);
            if (s[2] != 64) {
              outArr[k + 1] = ((s[1] & 0x0f) << 4) | ((s[2] & 0x3c) >> 2);
              if (s[3] != 64) {
                outArr[k + 2] = ((s[2] & 0x03) << 6) | s[3];
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
    if (this.bB64ToGlue) {
      for (let i = 0; i < k; i++) {
        iG = outArr[i] & 0xff;
        outArr[i] = (outArr[i] ^ iDitherL & 0xff) & 0xff;
        iDitherR = this.mb64_rotr16(iDitherR, 1) ^ iG;
        iDitherL = this.mb64_rotl16(iDitherL, 1) ^ iDitherR;
      }
     }
    outArr[k] = 0;
    return k;
  }

  static getCodesFromString(s) {
    let charCodeArr = [];
    for (let i = 0; i < s.length; ++i) {
      let code = s.charCodeAt(i);
      charCodeArr.push(code);
    }
    return charCodeArr;
  }

  static getStringFromCodes(iInput, iLength) {
    let sOutput = "";
    for (let i = 0; i < iInput.length; ++i) {
      if (iInput[i] > 0) {
        sOutput += String.fromCharCode(iInput[i]);
      } else {
        return sOutput;
      }
    }
    return sOutput;
  }

  // static main() {
  //   console.log('B64 encryptor demonstration');
 
  //   let iCryptKey = new Array(128, 12345, 67890);

  //   this.b64_set_key_i(iCryptKey, 1);
  //   console.log('Crypt key: 0x' + iCryptKey.toString(16));
  //   console.log('B64 code table: ' + this.iB64Code.join(', '));
  //   console.log('B64 code index table: ' + this.iB64Index.join(', '));
  //   let sTest =
  //     '000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.';
  //   let sBufferDe = new Array(256);
  //   let sBufferEn = new Array(342);
  //   let iSourceSize = 0;
  //   let iEncodedSize = 0;
  //   let iDecodedSize = 0;
  //   iSourceSize = sTest.length;
  //   console.log('Plain text: ' + sTest);
  //   console.log('Plain text size ' + iSourceSize);
  //   iEncodedSize = this.b64_encode(
  //     this.getCodesFromString(sTest),
  //     iSourceSize,
  //     sBufferEn
  //   );
  //   console.log('Crypt text: ' + sBufferEn.join(''));
  //   console.log('Crypt text size: ' + iEncodedSize);
  //   iDecodedSize = this.b64_decode(
  //     sBufferEn,
  //     iEncodedSize,
  //     sBufferDe
  //   );
  //   //console.log(sBufferDe)
  //   console.log('Decrypt text: ' + this.getStringFromCodes(sBufferDe));
  //   console.log('Decrypted size: ' + iDecodedSize);

  //   let iTS = Date.now();
  //   let iExperiments = 123456;
  //   let iProgressPrev = 0;
  //   let iProgress = 0;
  //   let iMsgSize = 80;
  //   for (let i = 0; i < iExperiments; ++i) {
  //     sBufferDe = new Array(256);
  //     sBufferEn = new Array(342);
  //     iMsgSize = i % 256;
  //     iCryptKey[0] = Date.now();
  //     iCryptKey[1] = Date.now();
  //     iCryptKey[2] = Date.now();
  //     this.b64_set_key_i(iCryptKey, iCryptKey.length);
  //     for (let i1 = 0; i1 < iMsgSize; ++i1) {
  //       sBufferDe[i1] = (i1 + i) & 0xff;
  //     }
  //     iEncodedSize = this.b64_encode(sBufferDe, iMsgSize, sBufferEn);
  //     iDecodedSize = this.b64_decode(sBufferEn, iEncodedSize, sBufferDe);
  //     for (let i1 = 0; i1 < iMsgSize; ++i1) {
  //       if (sBufferDe[i1] != ((i1 + i) & 0xff)) {
  //         console.log(
  //           'ERR: ' + i + ', ' + i1 + ', ' + iMsgSize + ', ' + sBufferDe[i1] + ' != ' + ((i1 + i) & 0xff) + ', ' + sBufferEn.join('')
  //         );
  //         return;
  //       }
  //     }
  //     iProgress = ((i * 100) / iExperiments) | 0;
  //     if (iProgressPrev !== iProgress) {
  //       console.log(
  //         'Progress: ' +
  //         iProgress +
  //         '%, ' +
  //         sBufferEn.join('')
  //       );
  //       iProgressPrev = iProgress;
  //     }
  //   }
  //   console.log('Time (millis): ' + (Date.now() - iTS));
  // }

  static main() {
    console.log("B64 encryptor demonstration");
  
    for (let i = 0; i < 32; ++i) {
      console.log(` ${this.mb64_rotl16(0xa5, i)}, `);
    }
  
    console.log();
  
    for (let i = 0; i < 32; ++i) {
      console.log(` ${this.mb64_rotr16(0xa5, i)}, `);
    }
  
    console.log();
  
    const sTest = "000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.".split('').map(c => c.charCodeAt(0));
    let sBufferDe = new Array(256);
    let sBufferEn = new Array(342);
    let iSourceSize = 0;
    let iEncodedSize = 0;
    let iDecodedSize = 0;
  
    iSourceSize = sTest.length;
    const iCryptKey = [128, 12345, 67890];
  
    console.log(`Plain text: ${String.fromCharCode(...sTest)}`);
    console.log(iSourceSize);
    console.log("-----------------------------------------------------------------------");
    console.log("Standard Base64 encoding");
  
    this.b64_set_key_i(null, 0);
    console.log(`B64 code table: ${this.iB64Code}`);
    console.log(`B64 code index table: ${this.iB64Index}`);
  
    iEncodedSize = this.b64_encode(sTest, sTest.length, sBufferEn, 16);
    console.log("Standard Base64 encoded text:");
    console.log(sBufferEn.join(''));
    console.log(iEncodedSize);
  
    iDecodedSize = this.b64_decode(sBufferEn, iEncodedSize, sBufferDe);
    console.log("Standard Base64 decoded text:");
    console.log(String.fromCharCode(...sBufferDe.slice(0, iDecodedSize)));
    console.log(iDecodedSize);
    console.log("-----------------------------------------------------------------------");
  
    sBufferDe = new Array(256);
    sBufferEn = new Array(342);
    console.log("Encryption with int[] as key: " + iCryptKey.join(' '));
    this.b64_set_key_i(iCryptKey, iCryptKey.length);
    console.log(`B64 code table: ${this.iB64Code}`);
    console.log(`B64 code index table: ${this.iB64Index}`);
    iEncodedSize = this.b64_encode(sTest, sTest.length, sBufferEn, 32);
    console.log("Encrypted text:");
    console.log(sBufferEn.join(''));
    console.log(iEncodedSize);
    iDecodedSize = this.b64_decode(sBufferEn, iEncodedSize, sBufferDe);
    console.log("Decrypted text:");
    console.log(String.fromCharCode(...sBufferDe.slice(0, iDecodedSize)));
    console.log(iDecodedSize);
    console.log("-----------------------------------------------------------------------");
  
    sBufferDe = new Array(256);
    sBufferEn = new Array(342);
    console.log("Encryption with String as key: " + "ThisIsTheKey1");
    this.b64_set_key_s("ThisIsTheKey1");
    console.log(`B64 code table: ${this.iB64Code}`);
    console.log(`B64 code index table: ${this.iB64Index}`);
    iEncodedSize = this.b64_encode(sTest, sTest.length, sBufferEn, 64);
    console.log("Encrypted text:");
    console.log(sBufferEn.join(''));
    console.log(iEncodedSize);
    iDecodedSize = this.b64_decode(sBufferEn, iEncodedSize, sBufferDe);
    console.log("Decrypted text:");
    console.log(String.fromCharCode(...sBufferDe.slice(0, iDecodedSize)));
    console.log(iDecodedSize);
    console.log("-----------------------------------------------------------------------");
  
    sBufferDe = new Array(256);
    sBufferEn = new Array(342);
    console.log("Encryption with int[0] as key: " + iCryptKey[0]);
    this.b64_set_key_i(iCryptKey, 1);
    console.log(`B64 code table: ${this.iB64Code}`);
    console.log(`B64 code index table: ${this.iB64Index}`);
    iEncodedSize = this.b64_encode(sTest, sTest.length, sBufferEn, 80);
    console.log("Encrypted text:");
    console.log(sBufferEn.join(''));
    console.log(iEncodedSize);
    iDecodedSize = this.b64_decode(sBufferEn, iEncodedSize, sBufferDe);
    console.log("Decrypted text:");
    console.log(String.fromCharCode(...sBufferDe.slice(0, iDecodedSize)));
    console.log(iDecodedSize);
    console.log("-----------------------------------------------------------------------");
  
    const iTS = Date.now();
    const iExperiments = 1234567;
    let iProgressPrev = 0;
    let iProgress = 0;
    let iMsgSize = 80;
    for (let i = 0; i < iExperiments; ++i) {
      iMsgSize = i % 256;
      iCryptKey[0] = Date.now();
      iCryptKey[1] = Date.now();
      iCryptKey[2] = Date.now();
      this.b64_set_key_i(iCryptKey, 3);
      sBufferDe = new Array(256);
      sBufferEn = new Array(342);
        for (let i1 = 0; i1 < iMsgSize; ++i1) {
        sBufferDe[i1] = ((i1 + i) & 0xff);
      }
      iEncodedSize = this.b64_encode(sBufferDe, iMsgSize, sBufferEn, 0);
      iDecodedSize = this.b64_decode(sBufferEn, iEncodedSize, sBufferDe);
      for (let i1 = 0; i1 < iMsgSize; ++i1) {
        if (sBufferDe[i1] !== ((i1 + i) & 0xff)) {
          console.log(`ERR: ${i}, ${sBufferEn.join('')}`);
          return;
        }
      }
      iProgress = Math.floor((i * 100) / iExperiments);
      if (iProgressPrev !== iProgress) {
        console.log(`Progress: ${iProgress}%, ${sBufferEn.join('')}`);
        iProgressPrev = iProgress;
      }
    }
    console.log(`Time (millis): ${Date.now() - iTS}`);
  }  

}

B64Encryptor.main();
