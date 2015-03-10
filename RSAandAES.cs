using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSAandAES
{
    class Program
    {
        static StreamWriter sw = new StreamWriter(@"D:\rsaaes.txt");

        static void Main(string[] args)
        {
            sw.WriteLine("\n-----RSA with AES-----\n");
            
            RijndaelManaged aes = CreateAesKey(128);
            byte[] keyAes = aes.Key;
            byte[] IV = aes.IV;            
            string plainText = "Hello RSA with AES!";
            byte[] cipherData = AesEncryption(plainText, keyAes, IV);
            sw.WriteLine("Cipher Data: {0}", Convert.ToBase64String(cipherData));

            RSACryptoServiceProvider rsaXml = CreateRsaKeyPair(2048);
            string publicKeyXml = rsaXml.ToXmlString(false);
            string privateKeyXml = rsaXml.ToXmlString(true);
            byte[] cipherAesKey = RsaEncryption("XML", Convert.ToBase64String(keyAes), publicKeyXml);
            sw.WriteLine("Cipher AesKey : {0}", Convert.ToBase64String(cipherAesKey));

            string plainTextAesKey = RsaDecryption("XML", cipherAesKey, privateKeyXml);
            sw.WriteLine("PlainText AesKey : {0}", plainTextAesKey);

            string plainTextData = AesDecryption(cipherData, Convert.FromBase64String(plainTextAesKey), IV);
            sw.WriteLine("PlainText Data : {0}", plainTextData);

            sw.Close();
        }

        
        static public RSACryptoServiceProvider CreateRsaKeyPair(int keySize)
        {
            var csp = new RSACryptoServiceProvider(keySize);
            
            return csp;
        }

        static byte[] RsaEncryption(string keyType, string plainText, string publicKey)
        {
            var cspEncryption = new RSACryptoServiceProvider();
            keyType = keyType.ToUpper();
            if (keyType == "XML")
            {
                cspEncryption.FromXmlString(publicKey);
            }
            else if (keyType == "BLOB")
            {
                cspEncryption.ImportCspBlob(Convert.FromBase64String(publicKey));
            }
            var bytesPlainTextData = Encoding.UTF8.GetBytes(plainText);
            var bytesCypherText = cspEncryption.Encrypt(bytesPlainTextData, false);

            return bytesCypherText;
        }

        static string RsaDecryption(string keyType, byte[] cipherText, string privateKey)
        {
            var cspDecryption = new RSACryptoServiceProvider();
            keyType = keyType.ToUpper();
            if (keyType == "XML")
            {
                cspDecryption.FromXmlString(privateKey);
            }
            else if (keyType == "BLOB")
            {
                cspDecryption.ImportCspBlob(Convert.FromBase64String(privateKey));
            }
            var bytesPlainTextData = cspDecryption.Decrypt(cipherText, false);

            return Encoding.UTF8.GetString(bytesPlainTextData);
        }

        static public RijndaelManaged CreateAesKey(int keySize)
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.KeySize = keySize;

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
