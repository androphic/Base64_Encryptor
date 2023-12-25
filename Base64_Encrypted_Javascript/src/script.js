class C64 {
  constructor() {
      this.S_ALPHABET_STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
      this.S_ALPHABET_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
      this.S_ALPHABET_QWERTY = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890-_=";
      this.S_ALPHABET_IMAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,=";
      this.S_ALPHABET_HQX = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr=";
      this.S_ALPHABET_CRYPT = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=";
      this.S_ALPHABET_GEDCOM = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=";
      this.S_ALPHABET_BCRYPT = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=";
      this.S_ALPHABET_XX = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=";
      this.S_ALPHABET_BASH = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@_=";

      this.I_LINE_STANDARD = 0;
      this.I_LINE_MIME = 76;
      this.I_LINE_PEM = 64;

      this.cAlphabet = new Array(65);
      this.iAlphabetIndex = new Array(128).fill(0);
      this.bInitialized = false;
      this.bToGlue = false;

      this.oEncState = this.createState();
      this.oDecState = this.createState();
  }

  createState() {
      return {
          iBuf: new Array(4).fill(0),
          iB: 0,
          iDR: 0xa55a,
          iDL: 0x55aa,
          iG: 0,
          iLineLen: 0,
          init() {
              this.iBuf.fill(0);
              this.iB = 0;
              this.iDR = 0xa55a;
              this.iDL = 0x55aa;
              this.iG = 0;
              this.iLineLen = 0;
          },
      };
  }

  rotl16(n, c) {
      n = n & 0xFFFF;
      c &= 15;
      return ((n << c) | (n >>> (16 - c))) & 0xFFFF;
  }

  rotr16(n, c) {
      n = n & 0xFFFF;
      c &= 15;
      return ((n >>> c) | (n << (16 - c))) & 0xFFFF;
  }

  shuffleCodeTable(iKey) {
      let iDitherForKey = 0x5aa5;
      for (let i = 0; i < 64; ++i) {
          iKey = this.rotl16(iKey, 1);
          iDitherForKey = this.rotr16(iDitherForKey, 1);
          let iSwitchIndex = i + (iKey ^ iDitherForKey) % (64 - i);
          let temp = this.cAlphabet[i];
          this.cAlphabet[i] = this.cAlphabet[iSwitchIndex];
          this.cAlphabet[iSwitchIndex] = temp;
      }
  }

  setAlphabet(sAlphabet) {
      if (!sAlphabet || sAlphabet.length !== 65) {
          this.cAlphabet = this.S_ALPHABET_STANDARD.split('');
          return;
      }
      this.cAlphabet = sAlphabet.split('');
      this.iAlphabetIndex.fill(0);
      for (let i = 0; i < this.cAlphabet.length; ++i) {
          this.cAlphabet[i] = String.fromCharCode(this.cAlphabet[i].charCodeAt(0) & 0x7f);
          if (this.iAlphabetIndex[this.cAlphabet[i]] === 0) {
              this.iAlphabetIndex[this.cAlphabet[i]] = 1;
          } else {
              this.cAlphabet = this.S_ALPHABET_STANDARD.split('');
              return;
          }
      }
  }

  initTables(sAlphabet) {
      this.bToGlue = false;
      this.bInitialized = false;
      this.resetStates();
      this.setAlphabet(sAlphabet);
  }

  indexTables() {
      this.iAlphabetIndex.fill(255);
      for (let i = 0; i < this.cAlphabet.length; ++i) {
          this.iAlphabetIndex[this.cAlphabet[i].charCodeAt(0)] = i;
      }
  }

  setEncryption(iKey, iKeyLength, sAlphabet) {
      this.initTables(sAlphabet);
      if (iKey) {
          if (!iKeyLength || iKeyLength > iKey.length) {
              iKeyLength = iKey.length;
          }
          for (let i = 0; i < iKeyLength; ++i) {
              this.shuffleCodeTable(iKey[i]);
          }
          this.bToGlue = true;
      }
      this.indexTables();
      this.bInitialized = true;
  }

  calcEncryptedLen(iInputLen, iLineLength, bPadding) {
      iLineLength = Math.floor(iLineLength / 4) * 4;
      let iOutputLen = Math.floor(iInputLen / 3) * 4;
      if (iLineLength > 0) {
          iOutputLen += Math.floor(iOutputLen / iLineLength) * 2;
      }
      if (iInputLen % 3 === 1) {
          iOutputLen += 2;
          if (bPadding) {
              iOutputLen += 2;
          }
      } else if (iInputLen % 3 === 2) {
          iOutputLen += 3;
          if (bPadding) {
              iOutputLen += 1;
          }
      }
      return iOutputLen;
  }

  calcDecryptedLen(iInputSize, iLineLength, bPadding) {
      iLineLength = Math.floor(iLineLength / 4) * 4;
      let iOutputLen;
      if (iLineLength > 0) {
          iInputSize -= Math.floor(iInputSize / (iLineLength + 2)) * 2;
      }
      iOutputLen = Math.floor(iInputSize / 4) * 3;
      if (!bPadding) {
          if (iInputSize % 4 === 2) {
              iOutputLen += 1;
          } else if (iInputSize % 4 === 3) {
              iOutputLen += 2;
          }
      }
      return iOutputLen;
  }

  resetStates() {
      this.oEncState.init();
      this.oDecState.init();
  }

  encrypt(iIn, iInLen, iOut, iLineMaxLen, bPadding) {
      if (!this.bInitialized) {
          this.setEncryption(null, 0, null);
      }
      iLineMaxLen = Math.floor(iLineMaxLen / 4) * 4;
      let o = this.oEncState;
      let k = 0;
      for (let i =0; i < iInLen; i++) {
        if (this.bToGlue) {
            o.iG = (iIn[i] ^ o.iDL & 0xff) & 0xff;
            o.iBuf[o.iB] = o.iG;
            o.iDR = this.rotr16(o.iDR, 1) ^ o.iG;
            o.iDL = this.rotl16(o.iDL, 1) ^ o.iDR;
        } else {
            o.iBuf[o.iB] = iIn[i];
        }
        ++o.iB;
        if (o.iB === 3) {
            iOut[k + 0] = this.cAlphabet[(o.iBuf[0] & 255) >> 2];
            iOut[k + 1] = this.cAlphabet[((o.iBuf[0] & 0x03) << 4) | ((o.iBuf[1] & 0xF0) >> 4)];
            iOut[k + 2] = this.cAlphabet[((o.iBuf[1] & 0x0F) << 2) | ((o.iBuf[2] & 0xC0) >> 6)];
            iOut[k + 3] = this.cAlphabet[o.iBuf[2] & 0x3F];
            o.iB = 0;
            k += 4;
            o.iLineLen += 4;
            if (iLineMaxLen > 0) {
                if (o.iLineLen >= iLineMaxLen) {
                    iOut[k] = '\r';
                    ++k;
                    iOut[k] = '\n';
                    ++k;
                    o.iLineLen = 0;
                }
            }
        }
    }
    if (o.iB !== 0) {
        if (o.iB === 1) {
            o.iBuf[1] = 0;
        }
        iOut[k + 0] = this.cAlphabet[(o.iBuf[0] & 255) >> 2];
        iOut[k + 1] = this.cAlphabet[((o.iBuf[0] & 0x03) << 4) | ((o.iBuf[1] & 0xF0) >> 4)];
        k += 2;
        o.iLineLen += 2;
        if (o.iB === 2) {
            iOut[k] = this.cAlphabet[((o.iBuf[1] & 0x0F) << 2)];
            ++k;
            ++o.iLineLen;
        } else {
            if (bPadding) {
                iOut[k] = this.cAlphabet[64];
                ++k;
                ++o.iLineLen;
            }
        }
        if (bPadding) {
            iOut[k] = this.cAlphabet[64];
            ++k;
            ++o.iLineLen;
        }
    }
    iOut[k] = '\0';
    return k;
}

decrypt(input, in_len, out) {
    if (!this.bInitialized) {
        this.setEncryption(null, 0, null);
    }
    let o = this.oDecState;
    let k = 0;
    for (let i = 0; i < in_len; ++i) {
        o.iBuf[o.iB] = this.iAlphabetIndex[input[i].charCodeAt(0)];
        if (o.iBuf[o.iB] !== 255) {
            ++o.iB;
            if (o.iB === 4) {
                if (o.iBuf[0] !== 64) {
                    if (o.iBuf[1] !== 64) {
                        out[k + 0] = (o.iBuf[0] & 255) << 2 | (o.iBuf[1] & 0x30) >> 4;
                        if (o.iBuf[2] !== 64) {
                            out[k + 1] = (o.iBuf[1] & 0x0F) << 4 | (o.iBuf[2] & 0x3C) >> 2;
                            if (o.iBuf[3] !== 64) {
                                out[k + 2] = (o.iBuf[2] & 0x03) << 6 | o.iBuf[3];
                                k += 3;
                            } else {
                                k += 2;
                            }
                        } else {
                            k += 1;
                        }
                    }
                }
                o.iB = 0;
            }
        }
    }
    if (o.iB >= 2) {
        out[k] = (o.iBuf[0] & 255) << 2 | (o.iBuf[1] & 0x30) >> 4;
        ++k;
    }
    if (o.iB === 3) {
        out[k] = (o.iBuf[1] & 0x0F) << 4 | (o.iBuf[2] & 0x3C) >> 2;
        ++k;
    }
    if (this.bToGlue) {
        for (let i = 0; i < k; ++i) {
            o.iG = out[i] & 0xff;
            out[i] = (out[i] ^ o.iDL & 0xff) & 0xff;
            o.iDR = this.rotr16(o.iDR, 1) ^ o.iG;
            o.iDL = this.rotl16(o.iDL, 1) ^ o.iDR;
        }
    }
    out[k] = '\0';
    return k;
}

static main() {
    var o = new C64();
    console.log("B64 encryptor demonstration");
  
    for (let i = 0; i < 32; ++i) {
      console.log(` ${o.rotl16(0xa5, i)}, `);
    }
  
    console.log();
  
    for (let i = 0; i < 32; ++i) {
      console.log(` ${o.rotr16(0xa5, i)}, `);
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
    o.setEncryption(null, 0, o.S_ALPHABET_STANDARD);
    console.log(`B64 code table: ${o.cAlphabet}`);
    console.log(`B64 code index table: ${o.iAlphabetIndex}`);
    iEncodedSize = o.encrypt(sTest, sTest.length, sBufferEn, 17, true);
    console.log("Standard Base64 encoded text:");
    console.log(sBufferEn.join(''));
    console.log(iEncodedSize);
    iDecodedSize = o.decrypt(sBufferEn, iEncodedSize, sBufferDe);
    console.log("Standard Base64 decoded text:");
    console.log(String.fromCharCode(...sBufferDe.slice(0, iDecodedSize)));
    console.log(iDecodedSize);
    console.log("-----------------------------------------------------------------------");
    console.log("Encryption with int[] as key: " + iCryptKey.join(' '));
    sBufferDe = new Array(256);
    sBufferEn = new Array(342);
    o.setEncryption(iCryptKey, iCryptKey.length, o.S_ALPHABET_STANDARD);
    console.log(`B64 code table: ${o.cAlphabet}`);
    console.log(`B64 code index table: ${o.iAlphabetIndex}`);
    iEncodedSize = o.encrypt(sTest, sTest.length, sBufferEn, o.I_LINE_PEM, true);
    console.log("Standard Base64 encoded text:");
    console.log(sBufferEn.join(''));
    console.log(iEncodedSize);
    iDecodedSize = o.decrypt(sBufferEn, iEncodedSize, sBufferDe);
    console.log("Standard Base64 decoded text:");
    console.log(String.fromCharCode(...sBufferDe.slice(0, iDecodedSize)));
    console.log(iDecodedSize);
    console.log("-----------------------------------------------------------------------");
  }
}

C64.main();
