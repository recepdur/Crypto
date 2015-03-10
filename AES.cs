using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AES
{
    class Program
    {
        static StreamWriter sw = new StreamWriter(@"D:\aes.txt");

        static void Main(string[] args)
        {
            sw.WriteLine("\n-----AES-----");
            RijndaelManaged aes = CreateAesKey(128);
            byte[] key = aes.Key;
            byte[] IV = aes.IV;
            string plainText = "Hello AES!";
            byte[] cipher = AesEncryption(plainText, key, IV);
            sw.WriteLine("Cipher: {0}", Convert.ToBase64String(cipher));
            string cipherToPlainText = AesDecryption(cipher, key, IV);
            sw.WriteLine("PlainText: {0}\n", cipherToPlainText);

            sw.Close();
        }

        static public RijndaelManaged CreateAesKey(int keySize)
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.KeySize = keySize;

            sw.WriteLine("BlockSize: {0}", aes.BlockSize);
            sw.WriteLine("FeedbackSize: {0}", aes.FeedbackSize);
            sw.WriteLine("IV: {0}", Convert.ToBase64String(aes.IV));
            sw.WriteLine("Key: {0}", Convert.ToBase64String(aes.Key));
            sw.WriteLine("Key Size: {0}", aes.KeySize);
            sw.WriteLine("Mode: {0}", aes.Mode);
            sw.WriteLine("Padding: {0}\n", aes.Padding);

            return aes;
        }

        static byte[] AesEncryption(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }

        static string AesDecryption(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }       

    }
}

