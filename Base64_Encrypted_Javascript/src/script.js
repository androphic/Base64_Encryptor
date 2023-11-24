class B64Encryptor {
  static bInitialized = false;
  static b64_code = new Array(65);
  static b64_index = new Array(65);

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
      return 64;
    }
  }

  static rotl16(n, c) {
    n = n & 0xffff;
    c &= 15;
    return ((n << c) | (n >> (16 - c))) & 0xffff;
  }

  static rotr16(n, c) {
    n = n & 0xffff;
    c &= 15;
    return ((n >> c) | (n << (16 - c))) & 0xffff;
  }

  static b64_int_from_index(ch) {
    if (ch == '=') {
      return 64;
    } else {
      return this.b64_index[this.b64_int(ch)];
    }
  }

  static b64_shuffle(iKey) {
    let iDither = 0x5aa5;
    for (let i = 0; i < 64; ++i) {
      iKey = this.rotl16(iKey, 1);
      iDither = this.rotr16(iDither, 1);
      let iSwitchIndex = i + ((iKey ^ iDither) % (64 - i));
      let iA = this.b64_code[i];
      this.b64_code[i] = this.b64_code[iSwitchIndex];
      this.b64_code[iSwitchIndex] = iA;
    }
    for (let i = 0; i < 64; ++i) {
      this.b64_index[this.b64_int(this.b64_code[i])] = i;
    }
  }

  static b64_init(iKey) {
    let sB64Chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    for (let i = 0; i < 64; ++i) {
      this.b64_index[i] = i & 0xff;
      this.b64_code[i] = sB64Chars[i];
    }
    this.b64_code[64] = 64;
    this.b64_shuffle(iKey);
    this.bInitialized = true;
  }

  static b64e_size(in_size) {
    return ((in_size - 1) / 3) * 4 + 4;
  }

  static b64d_size(in_size) {
    return (3 * in_size) / 4;
  }

  static b64_encode(inArr, in_len, outArr) {
    if (!this.bInitialized) {
      this.b64_init(0);
    }
    let i = 0,
      j = 0,
      k = 0;
    let s = new Array(3);
    let iDither = 0xa55a;
    let iG = 0;
    for (i = 0; i < in_len; i++) {
      //Glueing
      iG = (inArr[i] ^ iDither & 0xff) & 0xff;
      s[j] = iG;
      ++j;
      iDither = this.rotr16(iDither, 1) ^ iG;
      // Not glueing
      // s[j] = inArr[i];
      // ++j;
      //

      if (j == 3) {
        outArr[k + 0] = this.b64_code[(s[0] & 255) >> 2];
        outArr[k + 1] =
          this.b64_code[((s[0] & 0x03) << 4) + ((s[1] & 0xf0) >> 4)];
        outArr[k + 2] =
          this.b64_code[((s[1] & 0x0f) << 2) + ((s[2] & 0xc0) >> 6)];
        outArr[k + 3] = this.b64_code[s[2] & 0x3f];
        j = 0;
        k += 4;
      }
    }
    if (j != 0) {
      if (j == 1) {
        s[1] = 0;
      }
      outArr[k + 0] = this.b64_code[(s[0] & 255) >> 2];
      outArr[k + 1] =
        this.b64_code[((s[0] & 0x03) << 4) + ((s[1] & 0xf0) >> 4)];
      if (j === 2) {
        outArr[k + 2] = this.b64_code[(s[1] & 0x0f) << 2];
      } else {
        outArr[k + 2] = '=';
      }
      outArr[k + 3] = '=';
      k += 4;
    }
    outArr[k] = '\0';
    return k;
  }

  static b64_decode(inArr, in_len, outArr) {
    if (!this.bInitialized) {
      this.b64_init(0);
    }
    let j = 0, k = 0;
    let s = new Array(4);
    let iDither = 0xa55a;
    let iG = 0;
    for (let i = 0; i < in_len; i++) {
      s[j] = this.b64_int_from_index(inArr[i]);
      ++j;
      if (j == 4) {
        if (s[1] != 64) {
          outArr[k + 0] = ((s[0] & 255) << 2) + ((s[1] & 0x30) >> 4);
          if (s[2] != 64) {
            outArr[k + 1] = ((s[1] & 0x0f) << 4) + ((s[2] & 0x3c) >> 2);
            if (s[3] != 64) {
              outArr[k + 2] = ((s[2] & 0x03) << 6) + s[3];
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
    // Unglueing
    for (let i = 0; i < k; i++) {
      iG = outArr[i] & 0xff;
      outArr[i] = (outArr[i] ^ iDither & 0xff) & 0xff;
      iDither = this.rotr16(iDither, 1) ^ iG;
    }
    //.
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

  static main() {
    console.log('B64 encryptor demonstration');
    // console.log('rotl:');
    // for (let i = 0; i < 32; ++i) {
    //   console.log(' ' + this.rotl16(0xa5, i) + ', ');
    // }
    // console.log('rotr:');
    // for (let i = 0; i < 32; ++i) {
    //   console.log(' ' + this.rotr16(0xa5, i) + ', ');
    // }
    // console.log();

    let iCryptKey = 128;
    this.b64_init(iCryptKey);
    console.log('Crypt key: 0x' + iCryptKey.toString(16));
    console.log('B64 code table: ' + this.b64_code.join(', '));
    console.log('B64 code index table: ' + this.b64_index.join(', '));
    let sTest =
      '000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov.';
    let sBufferDe = new Array(256);
    let sBufferEn = new Array(342);
    let iSourceSize = 0;
    let iEncodedSize = 0;
    let iDecodedSize = 0;
    iSourceSize = sTest.length;
    console.log('Plain text: ' + sTest);
    console.log('Plain text size ' + iSourceSize);
    iEncodedSize = this.b64_encode(
      this.getCodesFromString(sTest),
      iSourceSize,
      sBufferEn
    );
    console.log('Crypt text: ' + sBufferEn.join(''));
    console.log('Crypt text size: ' + iEncodedSize);
    iDecodedSize = this.b64_decode(
      sBufferEn,
      iEncodedSize,
      sBufferDe
    );
    //console.log(sBufferDe)
    console.log('Decrypt text: ' + this.getStringFromCodes(sBufferDe));
    console.log('Decrypted size: ' + iDecodedSize);

    let iTS = Date.now();
    let iExperiments = 12345678;
    let iProgressPrev = 0;
    let iProgress = 0;
    let iMsgSize = 80;
    for (let i = 0; i < iExperiments; ++i) {
      sBufferDe = new Array(256);
      sBufferEn = new Array(342);
      iMsgSize = i % 256;
      iCryptKey = Date.now();
      this.b64_init(iCryptKey);
      for (let i1 = 0; i1 < iMsgSize; ++i1) {
        sBufferDe[i1] = (i1 + i) & 0xff;
      }
      iEncodedSize = this.b64_encode(sBufferDe, iMsgSize, sBufferEn);
      iDecodedSize = this.b64_decode(sBufferEn, iEncodedSize, sBufferDe);
      for (let i1 = 0; i1 < iMsgSize; ++i1) {
        if (sBufferDe[i1] != ((i1 + i) & 0xff)) {
          console.log(
            'ERR: ' + i + ', ' + i1 + ', ' + iMsgSize + ', ' + sBufferDe[i1] + ' != ' + ((i1 + i) & 0xff) + ', ' + sBufferEn.join('')
          );
          return;
        }
      }
      iProgress = ((i * 100) / iExperiments) | 0;
      if (iProgressPrev !== iProgress) {
        console.log(
          'Progress: ' +
          iProgress +
          '%, ' +
          sBufferEn.join('')
        );
        iProgressPrev = iProgress;
      }
    }
    console.log('Time (millis): ' + (Date.now() - iTS));
  }
}

B64Encryptor.main();
