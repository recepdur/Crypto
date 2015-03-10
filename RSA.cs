
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSA
{
    class Program
    {
        static StreamWriter sw = new StreamWriter(@"D:\rsa.txt");

        static void Main(string[] args)
        {
            sw.WriteLine("\n----- RSA - XML -----\n");
            RSACryptoServiceProvider rsaXml = CreateRsaKeyPair(2048, "XML");
            string publicKeyXml = rsaXml.ToXmlString(false);
            string privateKeyXml = rsaXml.ToXmlString(true);
            string plainText = "Hello RSA!";
            byte[] cipherXml = RsaEncryption("XML", plainText, publicKeyXml);
            sw.WriteLine("Cipher XML: {0}", Convert.ToBase64String(cipherXml));
            string plainTextXml = RsaDecryption("XML", cipherXml, privateKeyXml);
            sw.WriteLine("PlainText XML: {0}\n", plainTextXml);

            sw.WriteLine("\n----- RSA - BLOB -----\n");
            RSACryptoServiceProvider rsaBlob = CreateRsaKeyPair(3072, "BLOB");
            string publicKeyBlob = Convert.ToBase64String(rsaBlob.ExportCspBlob(false));
            string privateKeyBlob = Convert.ToBase64String(rsaBlob.ExportCspBlob(true));
            byte[] cipherBlob = RsaEncryption("BLOB", "Hello RSA!", publicKeyBlob);
            sw.WriteLine("Cipher BLOB: {0}", Convert.ToBase64String(cipherBlob));
            string plainTextBlob = RsaDecryption("BLOB", cipherBlob, privateKeyBlob);
            sw.WriteLine("PlainText BLOB: {0}\n", plainTextBlob);

            sw.Close();
        }

        static public RSACryptoServiceProvider CreateRsaKeyPair(int keySize, string keyType)
        {
            var csp = new RSACryptoServiceProvider(keySize);
            keyType = keyType.ToUpper();
            if (keyType == "XML")
            {
                sw.WriteLine("Public Key XML: {0}", csp.ToXmlString(false).ToString());
                sw.WriteLine("Private Key XML: {0}", csp.ToXmlString(true).ToString());
            }
            else if (keyType == "BLOB")
            {
                sw.WriteLine("Public Key BLOB: {0}", Convert.ToBase64String(csp.ExportCspBlob(false)));
                sw.WriteLine("Private Key BLOB: {0}", Convert.ToBase64String(csp.ExportCspBlob(true)));
            }
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
    }

}
