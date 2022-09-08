using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

internal class Program
{
    private static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
        var result = Encrypt("", false);
        //foreach (var item in result) { Console.Write("{0:X} ", Convert.ToUInt32(item)); }
        //Console.WriteLine(result);
        var mac = getMac("", "");
    }

    public static string getMac(string text, string key)
    {
        // From eifd (our "text") = 93 77 45 C2 08 83 A1 BA D1 E0 41 93 72 2A 15 92 37 8F 81 A8 F1 DC 58 91 57 AE B0 F7 54 4F A1 BA
        // And kmac (the key) = 65 22 B4 E1 71 19 5B B2 18 22 3A 97 6C 04 01 11
        // we should get 1A D7 FB 6A 33 89 E0 17

        byte[] keyBytes = new byte[] { 0x65, 0x22, 0xB4, 0xE1, 0x71, 0x19, 0x5B, 0xB2, 0x18, 0x22, 0x3A, 0x97, 0x6C, 0x04, 0x01, 0x11 }; // StringToByteArray(key);
        byte[] data = new byte[] { 0x93, 0x77, 0x45, 0xC2, 0x08, 0x83, 0xA1, 0xBA, 0xD1, 0xE0, 0x41, 0x93, 0x72, 0x2A, 0x15, 0x92, 0x37, 0x8F, 0x81, 0xA8, 0xF1, 0xDC, 0x58, 0x91, 0x57, 0xAE, 0xB0, 0xF7, 0x54, 0x4F, 0xA1, 0xBA, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // Encoding.UTF8.GetBytes(text);

        // NOTE THE PADDING IN THE DATA! 0x80 + whatever is needed to reach a total of 8 bytes
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
    public static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
    }

    public static string BytesToHex(byte[] bytes)
    {
        return String.Concat(Array.ConvertAll(bytes, delegate (byte x) { return x.ToString("X2"); })).ToLower();
    }

    public static string Encrypt(string toEncrypt, bool useHashing)
    {
        byte[] keyArray;
        byte[] toEncryptArray = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x5A, 0x6E, 0x7E, 0x38, 0x51, 0x62, 0xB7, 0xA3, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F };// UTF8Encoding.UTF8.GetBytes(toEncrypt);

        //System.Configuration.AppSettingsReader settingsReader =
        //                                    new AppSettingsReader();
        // Get the key from config file

        //string key = (string)settingsReader.GetValue("SecurityKey",
        //                                                 typeof(String));

        //System.Windows.Forms.MessageBox.Show(key);
        //If hashing use get hashcode regards to your key
        //if (useHashing)
        //{
        //    MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
        //    keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
        //    //Always release the resources and flush data
        //    // of the Cryptographic service provide. Best Practice

        //    hashmd5.Clear();
        //}
        //else
        keyArray = new byte[] { 0x65, 0x22, 0xB4, 0xE1, 0x71, 0x19, 0x5B, 0xB2, 0x18, 0x22, 0x3A, 0x97, 0x6C, 0x04, 0x01, 0x11 };//UTF8Encoding.UTF8.GetBytes(key);

        TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
        //set the secret key for the tripleDES algorithm
        tdes.Key = keyArray;
        //mode of operation. there are other 4 modes.
        //We choose ECB(Electronic code Book)
        tdes.Mode = CipherMode.ECB;
        //padding mode(if any extra byte added)

        tdes.Padding = PaddingMode.PKCS7;

        ICryptoTransform cTransform = tdes.CreateEncryptor();
        //transform the specified region of bytes array to resultArray
        byte[] resultArray =
          cTransform.TransformFinalBlock(toEncryptArray, 0,
          toEncryptArray.Length);
        //Release resources held by TripleDes Encryptor
        tdes.Clear();
        //Return the encrypted data into unreadable string format
        foreach (var item in resultArray) { Console.Write("{0:X} ", Convert.ToUInt32(item)); }
        Console.WriteLine("");
        return Convert.ToBase64String(resultArray, 0, resultArray.Length);
    }
}