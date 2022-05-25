using System;
using SecSharp;
namespace SimpleEnclave
{
    [Enclave]
    class EnclaveHashWithArray
    {
        private void ObtainKey(byte[] keyOut)
        {
            for (int i = 0; i < keyOut.Length; i++)
                keyOut[i] = (byte)((0x12 * i) % 0xFF);
        }

        private void XorElement(byte[] key, byte val, byte[] opadOut)
        {
            for (int i = 0; i < key.Length; i++)
                opadOut[i] = (byte)(key[i] ^ val);
        }

        private void ConcatBuffer(byte[] b1, byte[] b2, byte[] resultOut)
        {
            for (int i = 0; i < b1.Length; i++)
                resultOut[i] = b1[i];

            for (int i = 0; i < b2.Length; i++)
                resultOut[i + b1.Length] = b2[i];
        }

        public void HMACSHA1(byte[] message, byte[] digestOut)
        {
            byte[] key = new byte[64];
            this.ObtainKey(key);

            byte[] oKey = new byte[64];
            this.XorElement(key, 0x5c, oKey);

            byte[] iKey = new byte[64];
            this.XorElement(key, 0x36, iKey);

            byte[] iKey_message = new byte[iKey.Length + message.Length];
            this.ConcatBuffer(iKey, message, iKey_message);

            byte[] innerHash = new byte[20];
            this.SHA1(iKey_message, innerHash);

            byte[] oKey_innerHash = new byte[oKey.Length + innerHash.Length];
            this.ConcatBuffer(oKey, innerHash, oKey_innerHash);
            this.SHA1(oKey_innerHash, digestOut);
        }

        private void UIntToByteArray(uint val, byte[] buf, int offset)
        {
            for (int i = 3; i >= 0; i--)
                buf[offset + 3 - i] = (byte)(val >> (8 * i));
        }

        public void SHA1(byte[] message, byte[] digestOut)
        {
            uint h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
            // Message length in 64-bit
            ulong ml = (ulong)(message.Length * 8);

            // Number of zero bytes
            int zeroPadLen = (56 - (message.Length + 1) % 64) % 64;

            // Array temp for calculation (message + zero pads + '1' bit byte + 8 byte 64bit message length)
            byte[] vs = new byte[message.Length + zeroPadLen + 1 + 8];

            // First one bit
            vs[message.Length] = 0x80;

            for (int i = 0; i < zeroPadLen; i++)
                vs[message.Length + i + 1] = 0;

            for (int i = 0; i < 8; i++)
            {
                vs[i + message.Length + zeroPadLen + 1] = (byte)((ml >> ((7 - i) * 8)) & 0xFF);
            }

            for (int i = 0; i < message.Length; i++)
            {
                vs[i] = message[i];
            }

            int iteration = vs.Length / 64;

            for (int i = 0; i < iteration; i++)
            {
                int iterationBaseIdx = i * 512 / 8;
                uint[] w = new uint[80];

                // Transform to 16 32-bit words
                for (int j = 0; j < 16; j++)
                {
                    w[j] = vs[iterationBaseIdx + j * 4 + 3]
                            | ((uint)vs[iterationBaseIdx + j * 4 + 2]) << 8
                            | ((uint)vs[iterationBaseIdx + j * 4 + 1]) << 16 |
                            ((uint)vs[iterationBaseIdx + j * 4]) << 24;
                }

                // Extend to 80 32-bit words
                for (int j = 16; j < 80; j++)
                {
                    uint num = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
                    w[j] = (num << 1) | (num >> 31);
                }

                // Hash for this chunk
                uint a = h0;
                uint b = h1;
                uint c = h2;
                uint d = h3;
                uint e = h4;

                for (int j = 0; j < 80; j++)
                {
                    uint f = 0, k = 0;
                    if (j <= 19)
                    {
                        f = (b & c) | (~b & d);
                        k = 0x5A827999;
                    }
                    else if (j <= 39)
                    {
                        f = b ^ c ^ d;
                        k = 0x6ED9EBA1;
                    }
                    else if (j <= 59)
                    {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDC;
                    }
                    else
                    {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6;
                    }

                    uint temp = ((a << 5) | (a >> 27)) + f + e + k + w[j];
                    e = d;
                    d = c;
                    c = (b << 30) | (b >> 2);
                    b = a;
                    a = temp;
                }
                h0 += a;
                h1 += b;
                h2 += c;
                h3 += d;
                h4 += e;
            }

            UIntToByteArray(h0, digestOut, 0);
            UIntToByteArray(h1, digestOut, 1 * 4);
            UIntToByteArray(h2, digestOut, 2 * 4);
            UIntToByteArray(h3, digestOut, 3 * 4);
            UIntToByteArray(h4, digestOut, 4 * 4);
        }
    }
}