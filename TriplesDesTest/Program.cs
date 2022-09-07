using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Macs;

internal class Program
{
    private static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");
        //var result = Encrypt("", false);
        ////foreach (var item in result) { Console.Write("{0:X} ", Convert.ToUInt32(item)); }
        //Console.WriteLine(result);
        var mac = GetMac();
    }

    public static string GetMac()
    {
        return "";
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