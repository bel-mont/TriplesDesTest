using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

// https://stackoverflow.com/questions/11413576/how-to-implement-triple-des-in-c-sharp-complete-example
// https://github.com/novotnyllc/bc-csharp
// https://bouncycastle.org/specifications.html
internal class Program
{
    static byte[] cardIdBytes = new byte[] { 0x41, 0x41, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x42, 0x42 };
    static byte[] cardBytesHashed = new byte[] { 0x65, 0x22, 0xB4, 0xE1, 0x71, 0x19, 0x5B, 0xB2, 0x18, 0x22, 0x3A, 0x97, 0x6C, 0x04, 0x01, 0x11, 0xBD, 0xC4, 0xAA, 0x25 };

    // first 16 bytes of the hashed card id
    static byte[] kmac = new byte[] { 0x65, 0x22, 0xB4, 0xE1, 0x71, 0x19, 0x5B, 0xB2, 0x18, 0x22, 0x3A, 0x97, 0x6C, 0x04, 0x01, 0x11 };
    // Exact same as kmac
    static byte[] kenc = new byte[] { 0x65, 0x22, 0xB4, 0xE1, 0x71, 0x19, 0x5B, 0xB2, 0x18, 0x22, 0x3A, 0x97, 0x6C, 0x04, 0x01, 0x11 };
    private static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
        // Obtained from ND.IFD, RND.ICC, K.IFD
        var combinedData = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x5A, 0x6E, 0x7E, 0x38, 0x51, 0x62, 0xB7, 0xA3, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F };//, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        Console.Write("Data to encrypt length ");
        Console.Write(combinedData.Length);
        Console.WriteLine("");
        //var expectedEif = Encrypt(combinedData);
        //var expectedEif = BCTripleDESEncrypt(combinedData, kenc);
        // Expected EIFD should be
        // 93 77 45 C2 08 83 A1 BA D1 E0 41 93 72 2A 15 92
        // 37 8F 81 A8 F1 DC 58 91 57 AE B0 F7 54 4F A1 BA
        //Console.WriteLine($"result EIFD length {expectedEif.Length}");
        //foreach (var item in expectedEif) { Console.Write("{0:X} ", Convert.ToUInt32(item)); }
        // first line should be 93 77 45 C2 08 83 A1 BA D1 E0 41 93 72 2A 15 92
        Console.WriteLine("");
        //foreach (var item in result) { Console.Write("{0:X} ", Convert.ToUInt32(item)); }
        //Console.WriteLine(result);
        // Step 5
        var eifd = new byte[] { 0x93, 0x77, 0x45, 0xC2, 0x08, 0x83, 0xA1, 0xBA, 0xD1, 0xE0, 0x41, 0x93, 0x72, 0x2A, 0x15, 0x92, 0x37, 0x8F, 0x81, 0xA8, 0xF1, 0xDC, 0x58, 0x91, 0x57, 0xAE, 0xB0, 0xF7, 0x54, 0x4F, 0xA1, 0xBA, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        //// Already added the 8 bytes of padding in eifd, from 0x80 and the zeros at the end
        var mac = getMac(eifd, kmac);
        Console.WriteLine();

        //// 6. send a secure message to card, which combines the command bytes + eifd + mac
        //// In theory we can already do this, so we will have to retest once we deploy some dev functions to AWS lambda.

        //// Receive a response back
        //// Sample response:

        //// E_ICC = 58 60 77 5B 4D 03 2C C5 64 BA 20 4B 8E A8 68 F6
        ////         94 A7 4E 74 75 A8 FE F2 40 58 8B DA 1A F4 96 CE
        //// NOTE THE PADDING
        var eicc = new byte[] { 0x58, 0x60, 0x77, 0x5B, 0x4D, 0x03, 0x2C, 0xC5, 0x64, 0xBA, 0x20, 0x4B, 0x8E, 0xA8, 0x68, 0xF6, 0x94, 0xA7, 0x4E, 0x74, 0x75, 0xA8, 0xFE, 0xF2, 0x40, 0x58, 0x8B, 0xDA, 0x1A, 0xF4, 0x96, 0xCE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        //// M_ICC = 59 38 8F D6 CD 45 24 8B // 90 00 the last 2 are the sw confirmation bytes

        //// 7. Verify card authentication MAC (Kmac calculates Retail MAC for E_ICC and compares with M_ICC)
        verifyResponse(eicc, kmac);
        Console.WriteLine("");
        Console.WriteLine(eicc.Length.ToString());
        // 8. Extract RND.ICC||RND.IFD||K.ICC (TDES decrypt E_ICC with Kenc)
        //Console.WriteLine("Decrypting...");

        //var decryptResult = Decrypt(eicc, kenc);



    }

    public static void verifyResponse(byte[] eicc, byte[] keyBytes)
    {
        // E_ICC = 58 60 77 5B 4D 03 2C C5 64 BA 20 4B 8E A8 68 F6
        //         94 A7 4E 74 75 A8 FE F2 40 58 8B DA 1A F4 96 CE
        //var eicc = new byte[] { 0x58, 0x60, 0x77, 0x5B, 0x4D, 0x03, 0x2C, 0xC5, 0x64, 0xBA, 0x20, 0x4B, 0x8E, 0xA8, 0x68, 0xF6, 0x94, 0xA7, 0x4E, 0x74, 0x75, 0xA8, 0xFE, 0xF2, 0x40, 0x58, 0x8B, 0xDA, 0x1A, 0xF4, 0x96, 0xCE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        // this needs padding as well!

        // M_ICC = 59 38 8F D6 CD 45 24 8B // 90 00 the last 2 are the sw confirmation bytes

        // the mac obtained from eicc + kmac should be the same as micc
        getMac(eicc, keyBytes);
    }

    public static string getMac(byte[] data, byte[] keyBytes)
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

    public static byte[] Encrypt(byte[] encryptByteData)
    {
        //byte[] keyArray = new byte[24];
        byte[] toEncryptArray = encryptByteData; // new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x5A, 0x6E, 0x7E, 0x38, 0x51, 0x62, 0xB7, 0xA3, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F };// UTF8Encoding.UTF8.GetBytes(toEncrypt);

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
        // The key has to be 24 bytes! Copy the first 8 bytes at the end of the key array. No clue WTF but that's just how it is.
        //keyArray =  kenc; //UTF8Encoding.UTF8.GetBytes(key);
        //Array.Copy(kenc, keyArray, kenc.Length);
        List<byte> keyList = new();
        foreach (byte b in kenc)
        {
            keyList.Add(b);
        }

        var first8Bytes = kenc[0..8];
        keyList.AddRange(first8Bytes);
        Console.WriteLine("My key data array");
        foreach (var item in keyList)
        {
            Console.Write("{0:X} ", item);
            Console.Write(", ");
        }
        Console.WriteLine($"\nfinal key list length {keyList.Count}");
        Console.WriteLine("");

        TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
        //set the secret key for the tripleDES algorithm
        tdes.Key = keyList.ToArray();
        //tdes.IV = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        //mode of operation. there are other 4 modes.
        //We choose ECB(Electronic code Book)
        tdes.Mode = CipherMode.ECB;
        //tdes.IV = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        tdes.KeySize = 192;
        tdes.BlockSize = 64;
        //padding mode(if any extra byte added)

        tdes.Padding = PaddingMode.None;

        ICryptoTransform cTransform = tdes.CreateEncryptor();
        //transform the specified region of bytes array to resultArray
        byte[] resultArray =
          cTransform.TransformFinalBlock(toEncryptArray, 0,
          toEncryptArray.Length);
        //Release resources held by TripleDes Encryptor
        tdes.Clear();
        //Return the encrypted data into unreadable string format
        //foreach (var item in resultArray) { Console.Write("{0:X} ", Convert.ToUInt32(item)); }
        //// first line should be 93 77 45 C2 08 83 A1 BA D1 E0 41 93 72 2A 15 92
        // 37 8F 81 A8 F1 DC 58 91 57 AE B0 F7 54 4F A1 BA
        //Console.WriteLine("");
        return resultArray;
        //return Convert.ToBase64String(resultArray, 0, resultArray.Length);
    }

    //public static byte[] Decrypt(byte[] dataToDecrypt, byte[] keyArray)
    //{
    //    //byte[] keyArray;
    //    //get the byte code of the string
    //    // Due to padding error, removed the extra padding
    //    byte[] toDecryptArray = dataToDecrypt;// new byte[] { 0x58, 0x60, 0x77, 0x5B, 0x4D, 0x03, 0x2C, 0xC5, 0x64, 0xBA, 0x20, 0x4B, 0x8E, 0xA8, 0x68, 0xF6, 0x94, 0xA7, 0x4E, 0x74, 0x75, 0xA8, 0xFE, 0xF2, 0x40, 0x58, 0x8B, 0xDA, 0x1A, 0xF4, 0x96, 0xCE };  // dataToDecrypt; // Convert.FromBase64String(cipherString);

    //    //System.Configuration.AppSettingsReader settingsReader =
    //    //                                    new AppSettingsReader();
    //    ////Get your key from config file to open the lock!
    //    //string key = (string)settingsReader.GetValue("SecurityKey",
    //    //                                             typeof(String));

    //    //if (useHashing)
    //    //{
    //    //    //if hashing was used get the hash code with regards to your key
    //    //    MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
    //    //    keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
    //    //    //release any resource held by the MD5CryptoServiceProvider

    //    //    hashmd5.Clear();
    //    //}
    //    //else
    //    //{
    //    //if hashing was not implemented get the byte code of the key
    //    //keyArray = kenc; // UTF8Encoding.UTF8.GetBytes(key);
    //    //}

    //    TripleDES tdes = TripleDES.Create();
    //    //set the secret key for the tripleDES algorithm
    //    tdes.Key = keyArray;
    //    //mode of operation. there are other 4 modes. 
    //    //We choose ECB(Electronic code Book)

    //    tdes.Mode = CipherMode.ECB;
    //    //padding mode(if any extra byte added)
    //    tdes.Padding = PaddingMode.PKCS7;

    //    ICryptoTransform cTransform = tdes.CreateDecryptor();
    //    byte[] resultArray = cTransform.TransformFinalBlock(
    //                         toDecryptArray, 0, toDecryptArray.Length);
    //    //Release resources held by TripleDes Encryptor                
    //    tdes.Clear();
    //    //return the Clear decrypted TEXT
    //    foreach (var item in resultArray) { Console.Write("{0:X} ", Convert.ToUInt32(item)); }
    //    Console.WriteLine("");
    //    return resultArray;
    //}

    //public static byte[] BCTripleDESEncrypt(byte[] toEncrypt, byte[] key)
    //{
    //    byte[] keyArray;
    //    byte[] toEncryptArray = toEncrypt; //  UTF8Encoding.UTF8.GetBytes(toEncrypt);

    //    //keyArray = key; // UTF8Encoding.UTF8.GetBytes(key);

    //    List<byte> keyList = new();
    //    foreach (byte b in key)
    //    {
    //        keyList.Add(b);
    //    }

    //    var first8Bytes = kenc[0..8];
    //    Console.Write("\n First 8 bytes length {0} \n", first8Bytes.Length);
    //    keyList.AddRange(first8Bytes);
    //    Console.WriteLine("My key data array");
    //    foreach (var item in keyList)
    //    {
    //        Console.Write("{0:X} ", item);
    //        Console.Write(", ");
    //    }


    //    //create Triple DES encryption engine
    //    // https://www.idc-online.com/technical_references/pdfs/information_technology/Bouncy_Castle_Net_Implementation_Triple_DES_Algorithm.pdf
    //    DesEdeEngine desedeEngine = new DesEdeEngine();

    //    //create a padded block cipher using the default PKCS7/PKCS5 padding
    //    BufferedBlockCipher bufferedCipher = new BufferedBlockCipher(desedeEngine);

    //    // Create the KeyParameter for the DES3 key generated. 
    //    KeyParameter keyparam = ParameterUtilities.CreateKeyParameter("DESEDE", keyList.ToArray());

    //    //initialize the output array
    //    byte[] output = new byte[bufferedCipher.GetOutputSize(toEncryptArray.Length)];
    //    bufferedCipher.Init(true, keyparam);

    //    //carry out the encryption
    //    output = bufferedCipher.DoFinal(toEncryptArray);

    //    //Return the encrypted data into unreadable string format
    //    return output; // Convert.ToBase64String(output, 0, output.Length);
    //}
}