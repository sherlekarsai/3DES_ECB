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

            string XOR1 = XOR.XORHexadecimal(c1, c2);
            string XOR2 = XOR.XORHexadecimal(XOR1, c3);
            var kcv = TDES.GetKcvDes(XOR2);
            byte[] ciphertext = TDES.EncryptDES_ECB(XOR2, "sai sherlekarsai sherlekarsai sherlekarsai sherlekarsai sherlekarsai sherlekarsai sherlekarsai sherlekarsai sherlekar");
            var cleartext = TDES.DecryptDES_ECB(XOR2, ciphertext);



        }
    }
    public class TDES
    {
    
       public static string DecryptDES_ECB(string StrKey, byte[] cipherText)
        {
            var Key = StringToByteArray(StrKey);
            var IV = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            string plaintext = null;
            // Create TripleDESCryptoServiceProvider  
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.ECB;
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
        public static byte[] EncryptDES_ECB(string key, string strdata)
        {
            var mkw = StringToByteArray(key);
            byte[] data = Encoding.UTF8.GetBytes(strdata);
            var iv = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
            des.Mode = CipherMode.ECB;
            des.GenerateIV();
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, des.CreateEncryptor(mkw, des.IV), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
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
