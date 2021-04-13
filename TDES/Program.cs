using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines; // Install-Package BouncyCastle -Version 1.8.5
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
namespace TDES
{
    class Program
    {


        // Use any sort of encoding you like. 

        static void Main(string[] args)
        {
            string c1 = "BEEF0976345501B4C73608F4CCBB6900";
            string c2 = "997B6C34D099568ABF00612497B1D9E5";
            string c3 = "1A5B77AAC09642135809B58F9D623347";

            string part = XOR.XORHexadecimal(c1, c2);
            string deckey = XOR.XORHexadecimal(part, c3);
            var kcv_Of_deckey = TDES.GetKcvDes(deckey);

            string emvKey = "87039A46A98CE0880E5301EB72B878FB";

            var Key = TDES.StringToByteArray(emvKey);
            var cipherText = TDES.StringToByteArray(deckey);
            var IV = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            byte[] DecArray = TDES.DecryptDES_Array(Key, IV, cipherText, PaddingMode.Zeros, CipherMode.ECB);

            var HexData = TDES.ByteArrayToString(DecArray);



        }
    }
    public class TDES
    {
        /// <summary>
        /// Example to use in your code
        /// </summary>
        /// <param name="StrKey"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        private static byte[] Decrypt_DESWrapper_Array(string StrKey, string data)
        {
            var Key = StringToByteArray(StrKey);
            var cipherText = StringToByteArray(StrKey);
            var IV = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            byte[] DecArray = DecryptDES_Array(Key, IV, cipherText, PaddingMode.Zeros, CipherMode.ECB);
            return DecArray;

        }
        public static byte[] DecryptDES_Array(byte[] Key,byte[] IV, byte[] cipherText, PaddingMode padMode, CipherMode ciperhMode)
        {
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.CBC;
                tdes.Padding = PaddingMode.Zeros;
                
                tdes.GenerateIV();
                // Create a decryptor  
                ICryptoTransform decryptor = tdes.CreateDecryptor(Key, IV);

                byte[] resultArray = decryptor.TransformFinalBlock(
                         cipherText, 0, cipherText.Length);
                return resultArray;
            }
        }
        /// <summary>
        /// Decrypt data using  Triple Des
        /// </summary>
        /// <param name="StrKey"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public static string DecryptDES_String(byte[] Key, byte[] IV, byte[] cipherText, PaddingMode padMode, CipherMode ciperhMode)
        {
            string plaintext = null;
            // Create TripleDESCryptoServiceProvider  
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = ciperhMode;
                tdes.Padding = padMode;

                tdes.GenerateIV();
                // Create a decryptor  
                ICryptoTransform decryptor = tdes.CreateDecryptor(Key, IV);

                // Create the streams used for decryption.  
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    // Create crypto stream  
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // Read crypto stream  
                        using (StreamReader reader = new StreamReader(cs))
                            plaintext = reader.ReadToEnd();


                    }
                }
            }
            return plaintext;
        }
        public static string GetKcvDes(string key)
        {
            var mkw = StringToByteArray(key);
            var iv = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] data = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
            des.Mode = CipherMode.ECB;
            des.GenerateIV();
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, des.CreateEncryptor(mkw, des.IV), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                    var pp1 = memoryStream.ToArray();
                    return ByteArrayToString(memoryStream.ToArray()).Remove(6);
                }
            }

        }
        public static byte[] EncryptDES_String(byte[] Key, byte[] IV, byte[] cipherText, PaddingMode padMode, CipherMode ciperhMode)
        {
            TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
            des.Mode = CipherMode.ECB;
            des.GenerateIV();
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, des.CreateEncryptor(Key, des.IV), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(cipherText, 0, cipherText.Length);
                    cryptoStream.FlushFinalBlock();
                    return memoryStream.ToArray();
                }
            }

        }
        public static string GetKcvAes(string key)
        {
            var iv = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            var data = new byte[key.Length];

            for (var i = 0; i < key.Length; i++)
            {
                data[i] = 0x00;
            }

            var csp = new AesCryptoServiceProvider();

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, csp.CreateEncryptor(StringToByteArray(key), iv), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                    return ByteArrayToString(memoryStream.ToArray()).Remove(6);
                }
            }
        }
        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        // C# Implementation to find the
        // XOR of the two Binary Strings
    }
    public class XOR
    {
        // Function to find the
        // XOR of the two Binary Strings
        public static string xoring(string a, string b, int n)
        {
            string ans = "";

            // Loop to iterate over the
            // Binary Strings
            for (int i = 0; i < n; i++)
            {
                // If the Character matches
                if (a[i] == b[i])
                    ans += "0";
                else
                    ans += "1";
            }
            return ans;
        }
        public static string HexToBinary(string c1)
        {
            var c1Arr = c1.ToCharArray();
            string res = "";
            for (int i = 0; i < c1.Length; i++)
            {
                string binarystring1 = String.Join(String.Empty, c1Arr[i].ToString().Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));
                res += binarystring1;
            }
            return res;
        }
        // Driver Code
        public static string XORHexadecimal(string c1, string c2)
        {
            var c1Arr = c1.ToCharArray();
            var c2Arr = c2.ToCharArray();
            string res = "";
            for (int i = 0; i < c1.Length; i++)
            {
                string binarystring1 = String.Join(String.Empty, c1Arr[i].ToString().Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));
                string binarystring2 = String.Join(String.Empty, c2Arr[i].ToString().Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));


                string restemp = xoring(binarystring1, binarystring2, 4);
                res += Convert.ToInt32(restemp, 2).ToString("X");
            }
            return res;
        }
        public static byte[] ConvertToByteArray(string str, Encoding encoding)
        {
            return encoding.GetBytes(str);
        }

        public static String ToBinary(Byte[] data)
        {
            return string.Join(" ", data.Select(byt => Convert.ToString(byt, 2).PadLeft(8, '0')));
        }

    }

    // This code is contributed by shubhamsingh10


}
