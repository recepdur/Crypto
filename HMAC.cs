using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HMAC
{
    class Program
    {
        static void Main(string[] args)
        {
            string key = "xe@k,ai";

            Console.WriteLine("MD5   : {0}", ComputeHash("qqqqq", key, "MD5"));
            Console.WriteLine("SHA1  : {0}", ComputeHash("qqqqq", key, "SHA1"));
            Console.WriteLine("SHA256: {0}", ComputeHash("qqqqq", key, "SHA256"));
            Console.WriteLine("SHA384: {0}", ComputeHash("qqqqq", key, "SHA384"));
            Console.WriteLine("SHA512: {0}", ComputeHash("qqqqq", key, "SHA512"));
            Console.Read();
        }

        public static string ComputeHash(string plainText, string key, string hashAlgorithm)
        {
            byte[] keyByte = Encoding.ASCII.GetBytes(key);
            byte[] messageBytes = Encoding.ASCII.GetBytes(plainText);
            byte[] hashMessage;

            switch (hashAlgorithm.ToUpper())
            {
                case "SHA1":
                    HMACSHA1 hmacsha1 = new HMACSHA1(keyByte);
                    hashMessage = hmacsha1.ComputeHash(messageBytes);
                    break;

                case "SHA256":
                    HMACSHA256 hmacsha256 = new HMACSHA256(keyByte);
                    hashMessage = hmacsha256.ComputeHash(messageBytes);
                    break;

                case "SHA384":
                    HMACSHA384 hmacsha384 = new HMACSHA384(keyByte);
                    hashMessage = hmacsha384.ComputeHash(messageBytes);
                    break;

                case "SHA512":
                    HMACSHA512 hmacsha512 = new HMACSHA512(keyByte);
                    hashMessage = hmacsha512.ComputeHash(messageBytes);
                    break;

                default:
                    HMACMD5 hmacmd5 = new HMACMD5(keyByte);
                    hashMessage = hmacmd5.ComputeHash(messageBytes);
                    break;
            }

            return ByteToString(hashMessage);
        }

        public static string ByteToString(byte[] buff)
        {
            string sbinary = "";

            for (int i = 0; i < buff.Length; i++)
            {
                sbinary += buff[i].ToString("X2"); // hex format
            }
            return (sbinary);
        }                

    }
}
