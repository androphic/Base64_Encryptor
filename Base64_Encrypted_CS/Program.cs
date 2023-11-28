//============================================================================
// Name        : Base64_Encrypted_CPP.cpp
// Author      : Tofig Kareemov
// Version     :
// Copyright   : Your copyright notice
// Description : C# implementation of Base64 Encryptor
//============================================================================

using System;
using System.Text;

    public class B64Encryptor
    {
        private readonly char[] iB64Code = new char[65];
        private readonly int[] iB64Index = new int[65];
        private bool bB64Initialized = false;
        private bool bB64ToGlue = false;

        private int Mb64Int(int ch)
        {
            if (ch == 61)
                return 64;
            else if (ch == 43)
                return 62;
            else if (ch == 47)
                return 63;
            else if (ch > 47 && ch < 58)
                return ch + 4;
            else if (ch > 64 && ch < 91)
                return ch - 'A';
            else if (ch > 96 && ch < 123)
                return (ch - 'a') + 26;
            return 255;
        }

        private int Mb64Rotl16(int n, int c)
        {
            n = n & 0xFFFF;
            c &= 15;
            return ((n << c) | (n >> (16 - c))) & 0xFFFF;
        }

        private int Mb64Rotr16(int n, int c)
        {
            n = n & 0xFFFF;
            c &= 15;
            return ((n >> c) | (n << (16 - c))) & 0xFFFF;
        }

        private int Mb64IntFromIndex(int ch)
        {
            int iCh = Mb64Int(ch);
            if (iCh == 255)
                return 255;
            return ch == 61 ? 64 : iB64Index[Mb64Int(ch)];
        }

        private void Mb64Shuffle(int iKey)
        {
            int iDither = 0x5aa5;
            for (int i = 0; i < 64; ++i)
            {
                iKey = Mb64Rotl16(iKey, 1);
                iDither = Mb64Rotr16(iDither, 1);
                int iSwitchIndex = i + (iKey ^ iDither) % (64 - i);
                char iA = iB64Code[i];
                iB64Code[i] = iB64Code[iSwitchIndex];
                iB64Code[iSwitchIndex] = iA;
            }
        }

        private void Mb64InitTables()
        {
            char[] sB64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".ToCharArray();
            for (int i = 0; i < 64; ++i)
            {
                iB64Index[i] = i & 0xff;
                iB64Code[i] = sB64Chars[i];
            }
            iB64Code[64] = '\0';
        }

        private void Mb64IndexTables()
        {
            for (int i = 0; i < 64; ++i)
                iB64Index[Mb64Int(iB64Code[i])] = i;
        }

        public void B64SetKeyI(int[] iKey, int iSize)
        {
            Mb64InitTables();
            if (iKey != null)
            {
                for (int i = 0; i < iSize; ++i)
                    Mb64Shuffle(iKey[i]);
                Mb64IndexTables();
                bB64ToGlue = true;
            }
            bB64Initialized = true;
        }

        public void B64SetKeyS(string sKey)
        {
            Mb64InitTables();
            if (sKey != null)
            {
                foreach (char c in sKey)
                    Mb64Shuffle(0 | c | (c << 8));
                Mb64IndexTables();
                bB64ToGlue = true;
            }
            bB64Initialized = true;
        }

        public int B64EncSize(int inSize)
        {
            return ((inSize - 1) / 3) * 4 + 4;
        }

        public int B64DecSize(int inSize)
        {
            return (3 * inSize) / 4;
        }

        public int B64Encode(byte[] input, int inLen, byte[] output, int iTextLineLength)
        {
            if (!bB64Initialized)
                B64SetKeyI(null, 0);

            int i = 0, j = 0, k = 0;
            int[] s = new int[3];
            int iDitherR = 0xa55a;
            int iDitherL = 0x55aa;
            int iG = 0;
            int iTextLineCount = 0;

            iTextLineLength = (iTextLineLength / 4) * 4;

            for (i = 0; i < inLen; i++)
            {
                if (bB64ToGlue)
                {
                    iG = ((input[i] ^ iDitherL & 0xff) & 0xff);
                    s[j] = iG;
                    iDitherR = Mb64Rotr16(iDitherR, 1) ^ iG;
                    iDitherL = Mb64Rotl16(iDitherL, 1) ^ iDitherR;
                }
                else
                {
                    s[j] = (byte)(input[i]);
                }

                ++j;

                if (j == 3)
                {
                    output[k + 0] = (byte)iB64Code[(s[0] & 255) >> 2];
                    output[k + 1] = (byte)iB64Code[((s[0] & 0x03) << 4) | ((s[1] & 0xF0) >> 4)];
                    output[k + 2] = (byte)iB64Code[((s[1] & 0x0F) << 2) | ((s[2] & 0xC0) >> 6)];
                    output[k + 3] = (byte)iB64Code[s[2] & 0x3F];

                    j = 0;
                    k += 4;

                    if (iTextLineLength > 0)
                    {
                        iTextLineCount += 4;
                        if (iTextLineCount >= iTextLineLength)
                        {
                            output[k] = (byte)'\n';
                            ++k;
                            iTextLineCount = 0;
                        }
                    }
                }
            }

            if (j != 0)
            {
                if (j == 1)
                    s[1] = 0;

                output[k + 0] = (byte)iB64Code[(s[0] & 255) >> 2];
                output[k + 1] = (byte)iB64Code[((s[0] & 0x03) << 4) | ((s[1] & 0xF0) >> 4)];

                if (j == 2)
                    output[k + 2] = (byte)iB64Code[((s[1] & 0x0F) << 2)];
                else
                    output[k + 2] = (byte)'=';

                output[k + 3] = (byte)'=';

                k += 4;

                if (iTextLineLength > 0)
                {
                    iTextLineCount += 4;
                    if (iTextLineCount >= iTextLineLength)
                    {
                        output[k] = (byte)'\n';
                        ++k;
                        iTextLineCount = 0;
                    }
                }
            }

            output[k] = (byte)'\0';

            return k;
        }

        public int B64Decode(byte[] input, int inLen, byte[] output)
        {
            if (!bB64Initialized)
                B64SetKeyI(null, 0);

            int j = 0, k = 0;
            int[] s = new int[4];
            int iDitherR = 0xa55a;
            int iDitherL = 0x55aa;
            int iG = 0;

            for (int i = 0; i < inLen; ++i)
            {
                s[j] = Mb64IntFromIndex(input[i]);

                if (s[j] != 255)
                {
                    ++j;
                    if (j == 4)
                    {
                        if (s[1] != 64)
                        {
                            output[k + 0] = (byte)(((s[0] & 255) << 2) | ((s[1] & 0x30) >> 4));

                            if (s[2] != 64)
                            {
                                output[k + 1] = (byte)(((s[1] & 0x0F) << 4) | ((s[2] & 0x3C) >> 2));

                                if (s[3] != 64)
                                {
                                    output[k + 2] = (byte)(((s[2] & 0x03) << 6) | (s[3]));
                                    k += 3;
                                }
                                else
                                {
                                    k += 2;
                                }
                            }
                            else
                            {
                                k += 1;
                            }
                        }

                        j = 0;
                    }
                }
            }

            // Unglueing
            if (bB64ToGlue)
            {
                for (int i = 0; i < k; ++i)
                {
                    iG = output[i] & 0xff;
                    output[i] = (byte)((output[i] ^ iDitherL & 0xff) & 0xff);
                    iDitherR = Mb64Rotr16(iDitherR, 1) ^ iG;
                    iDitherL = Mb64Rotl16(iDitherL, 1) ^ iDitherR;
                }
            }

            output[k] = (byte)'\0';

            return k;
        }
    public static void run()
    {
        B64Encryptor o = new B64Encryptor();
        Console.WriteLine("B64 encryptor demonstration");

        for (int i = 0; i < 32; ++i)
        {
            Console.Write(" " + o.Mb64Rotl16(0xa5, i) + ", ");
        }

        Console.WriteLine();

        for (int i = 0; i < 32; ++i)
        {
            Console.Write(" " + o.Mb64Rotr16(0xa5, i) + ", ");
        }

        Console.WriteLine();

        byte[] sTest = "000000000000000000000000000000000000000000000000000000000000000000000 Test 1234567890. Androphic. Tofig Kareemov."
            .Select(c => (byte)c).ToArray();
        byte[] sBufferDe = new byte[256];
        byte[] sBufferEn = new byte[256 * 4 / 3 + 1];
        int iSourceSize = 0;
        int iEncodedSize = 0;
        int iDecodedSize = 0;
        iSourceSize = sTest.Length;
        int[] iCryptKey = new int[] { 128, 12345, 67890 }; // (int) System.currentTimeMillis();

        Console.WriteLine("Plain text: " + new string(sTest.Select(b => (char)b).ToArray()));
        Console.WriteLine(iSourceSize);
        Console.WriteLine("-----------------------------------------------------------------------");
        Console.WriteLine("Standard Base64 encoding");
        o.B64SetKeyI(null, 0);
        Console.WriteLine("B64 code table: " + new string(o.iB64Code));
        Console.WriteLine("B64 code index table: " + string.Join(", ", o.iB64Index));
        iEncodedSize = o.B64Encode(sTest, sTest.Length, sBufferEn, 16);
        Console.WriteLine("Standard Base64 encoded text:");
        Console.WriteLine(new string(sBufferEn.Select(b => (char)b).ToArray()));
        Console.WriteLine(iEncodedSize);
        iDecodedSize = o.B64Decode(sBufferEn, iEncodedSize, sBufferDe);
        Console.WriteLine("Standard Base64 decoded text:");
        Console.WriteLine(new string(sBufferDe.Select(b => (char)b).ToArray()));
        Console.WriteLine(iDecodedSize);
        Console.WriteLine("-----------------------------------------------------------------------");
        sBufferDe = new byte[256];
        sBufferEn = new byte[256 * 4 / 3 + 1];
        Console.WriteLine("Encryption with int[] as key");
        o.B64SetKeyI(iCryptKey, iCryptKey.Length);
        Console.WriteLine("B64 code table: " + new string(o.iB64Code));
        Console.WriteLine("B64 code index table: " + string.Join(", ", o.iB64Index));
        iEncodedSize = o.B64Encode(sTest, sTest.Length, sBufferEn, 32);
        Console.WriteLine("Encrypted text:");
        Console.WriteLine(new string(sBufferEn.Select(b => (char)b).ToArray()));
        Console.WriteLine(iEncodedSize);
        iDecodedSize = o.B64Decode(sBufferEn, iEncodedSize, sBufferDe);
        Console.WriteLine("Decrypted text:");
        Console.WriteLine(new string(sBufferDe.Select(b => (char)b).ToArray()));
        Console.WriteLine(iDecodedSize);
        Console.WriteLine("-----------------------------------------------------------------------");
        sBufferDe = new byte[256];
        sBufferEn = new byte[256 * 4 / 3 + 1];
        Console.WriteLine("Encryption with String as key");
        o.B64SetKeyS("ThisIsTheKey1");
        Console.WriteLine("B64 code table: " + new string(o.iB64Code));
        Console.WriteLine("B64 code index table: " + string.Join(", ", o.iB64Index));
        iEncodedSize = o.B64Encode(sTest, sTest.Length, sBufferEn, 64);
        Console.WriteLine("Encrypted text:");
        Console.WriteLine(new string(sBufferEn.Select(b => (char)b).ToArray()));
        Console.WriteLine(iEncodedSize);
        iDecodedSize = o.B64Decode(sBufferEn, iEncodedSize, sBufferDe);
        Console.WriteLine("Decrypted text:");
        Console.WriteLine(new string(sBufferDe.Select(b => (char)b).ToArray()));
        Console.WriteLine(iDecodedSize);
        Console.WriteLine("-----------------------------------------------------------------------");
       sBufferDe = new byte[256];
        sBufferEn = new byte[256 * 4 / 3 + 1];
        Console.WriteLine("Encryption with int[] as key");
        o.B64SetKeyI(iCryptKey, 1);
        Console.WriteLine("B64 code table: " + new string(o.iB64Code));
        Console.WriteLine("B64 code index table: " + string.Join(", ", o.iB64Index));
        iEncodedSize = o.B64Encode(sTest, sTest.Length, sBufferEn, 80);
        Console.WriteLine("Encrypted text:");
        Console.WriteLine(new string(sBufferEn.Select(b => (char)b).ToArray()));
        Console.WriteLine(iEncodedSize);
        iDecodedSize = o.B64Decode(sBufferEn, iEncodedSize, sBufferDe);
        Console.WriteLine("Decrypted text:");
        Console.WriteLine(new string(sBufferDe.Select(b => (char)b).ToArray()));
        Console.WriteLine(iDecodedSize);
        Console.WriteLine("-----------------------------------------------------------------------");

        sBufferDe = new byte[256];
        sBufferEn = new byte[256 * 4 / 3 + 1];
        int iTS = (int)DateTimeOffset.Now.ToUnixTimeMilliseconds();
        long iExperiments = 1234567;
        int iProgressPrev = 0;
        int iProgress = 0;
        int iMsgSize = 80;
        var random = new Random();

        for (long i = 0; i < iExperiments; ++i)
        {
            iMsgSize = (int)(i % 256);

            iCryptKey[0] = random.Next(0, 65536);
            iCryptKey[1] = random.Next(0, 65536);
            iCryptKey[2] = random.Next(0, 65536);
            // iCryptKey[0] = (int)DateTimeOffset.Now.ToUnixTimeMilliseconds();
            // iCryptKey[1] = (int)DateTimeOffset.Now.ToUnixTimeMilliseconds();
            // iCryptKey[2] = (int)DateTimeOffset.Now.ToUnixTimeMilliseconds();
            o.B64SetKeyI(iCryptKey, 3);

            for (int i1 = 0; i1 < iMsgSize; ++i1)
            {
                sBufferDe[i1] = (byte)(i1 + i);
            }

            iEncodedSize = o.B64Encode(sBufferDe, iMsgSize, sBufferEn, 0);
            iDecodedSize = o.B64Decode(sBufferEn, iEncodedSize, sBufferDe);

            for (int i1 = 0; i1 < iMsgSize; ++i1)
            {
                if (sBufferDe[i1] != (byte)(i1 + i))
                {
                    Console.WriteLine("ERR: " + i + ", " + new string(sBufferEn.Select(b => (char)b).ToArray()));
                    return;
                }
            }

            iProgress = (int)(i * 100 / iExperiments);

            if (iProgressPrev != iProgress)
            {
                Console.WriteLine("Progress: " + iProgress + "%, " + new string(sBufferEn.Select(b => (char)b).ToArray()).Split('\0')[0]);
                iProgressPrev = iProgress;
            }
        }

        Console.WriteLine("Time (millis): " + ((int)DateTimeOffset.Now.ToUnixTimeMilliseconds() - iTS));
    }
}

class Program
{
    static void Main()
    {
        B64Encryptor.run();
    }
}
