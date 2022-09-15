using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TriplesDesTest.Cryptography
{
    class RetailMac
    {
        public string getMac(byte[] data, byte[] keyBytes)
        {
            // From eifd (our "text") = 93 77 45 C2 08 83 A1 BA D1 E0 41 93 72 2A 15 92 37 8F 81 A8 F1 DC 58 91 57 AE B0 F7 54 4F A1 BA
            // And kmac (the key) = 65 22 B4 E1 71 19 5B B2 18 22 3A 97 6C 04 01 11
            // we should get 1A D7 FB 6A 33 89 E0 17

            //byte[] keyBytes = kmac; // StringToByteArray(key);
            //byte[] data = new byte[] { 0x93, 0x77, 0x45, 0xC2, 0x08, 0x83, 0xA1, 0xBA, 0xD1, 0xE0, 0x41, 0x93, 0x72, 0x2A, 0x15, 0x92, 0x37, 0x8F, 0x81, 0xA8, 0xF1, 0xDC, 0x58, 0x91, 0x57, 0xAE, 0xB0, 0xF7, 0x54, 0x4F, 0xA1, 0xBA, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // Encoding.UTF8.GetBytes(text);

            // NOTE THE PADDING IN THE DATA! 0x80 + whatever is needed to reach a total of 8 bytes. This is padding method 2.
            // https://en.wikipedia.org/wiki/ISO/IEC_9797-1#Padding, https://stackoverflow.com/questions/6966419/iso-9797-padding-method-2-and-mac-generation-in-java
            // This is required to get the desired result, similar to how this is done when obtaining the eifd

            DesEngine cipher = new DesEngine();
            ISO9797Alg3Mac mac = new ISO9797Alg3Mac(cipher);

            KeyParameter keyP = new KeyParameter(keyBytes);
            mac.Init(keyP);
            mac.BlockUpdate(data, 0, data.Length);

            byte[] outPut = new byte[8];

            mac.DoFinal(outPut, 0);

            foreach (var item in outPut) { Console.Write("{0:X} ", Convert.ToUInt32(item)); }

            return BytesToHex(outPut);
        }
        public byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public string BytesToHex(byte[] bytes)
        {
            return String.Concat(Array.ConvertAll(bytes, delegate (byte x) { return x.ToString("X2"); })).ToLower();
        }
    }
}
