using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApplication1
{
    class Program
    {
        static void Main(string[] args)
        {
            string rawPassword = Console.ReadLine();
            Console.WriteLine("HashSha256 : " + getHashSha256(rawPassword));
            Console.WriteLine("ToBase64 : " + EncodePasswordToBase64(rawPassword));
            Console.WriteLine("Decode : " + DecodeFrom64(EncodePasswordToBase64(rawPassword)));
            Console.WriteLine("MD5 Hashing : " + getHashmd5(rawPassword));
            Console.WriteLine("HashSha1 : " + getHashSha1(rawPassword));
            Console.WriteLine("HashSha512 : " + getHashSha512(rawPassword));
        }
        //sha512
        public static string getHashSha512(string rawPassword)
        {
            UnicodeEncoding UE = new UnicodeEncoding();
            byte[] hashValue;
            byte[] message = UE.GetBytes(rawPassword);
            SHA512Managed hashString = new SHA512Managed();
            string encodedData = Convert.ToBase64String(message);
            string hex = "";
            hashValue = hashString.ComputeHash(UE.GetBytes(encodedData));

            foreach (byte  item in hashValue)
            {
                hex += string.Format("{0:x2}", item);
            }
            return hex;
        }

        //sha1
        private static string getHashSha1(string rawPassword)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(rawPassword));
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("X2"));
                }
                return sb.ToString();
            }
        }

        //HashSha256
        private static string getHashSha256(string rawPssword)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(rawPssword);
            SHA256Managed hashstring = new SHA256Managed();
            byte[] hash = hashstring.ComputeHash(bytes);
            string hashString = string.Empty;
            foreach (byte x in hash)
            {
                hashString += String.Format("{0:x2}", x);
            }
            return hashString;
        }

        //md5
        private static string getHashmd5(string rawPassword)
        {
            Byte[] originalBytes;
            Byte[] encodeBytes;
            MD5 md5;

            md5 = new MD5CryptoServiceProvider();
            originalBytes = ASCIIEncoding.Default.GetBytes(rawPassword);
            encodeBytes = md5.ComputeHash(originalBytes);

            return BitConverter.ToString(encodeBytes);
        }

        public static string DecodeFrom64(string encodedData)
        {
            System.Text.UTF8Encoding encoder = new System.Text.UTF8Encoding();
            System.Text.Decoder utf8Decode = encoder.GetDecoder();
            byte[] todecode_byte = Convert.FromBase64String(encodedData);
            int charCount = utf8Decode.GetCharCount(todecode_byte, 0, todecode_byte.Length);
            char[] decoded_char = new char[charCount];
            utf8Decode.GetChars(todecode_byte, 0, todecode_byte.Length, decoded_char, 0);
            string result = new String(decoded_char);
            return result;
        }

        private static string EncodePasswordToBase64(string rawPssword)
        {
            byte[] encData_byte = new byte[rawPssword.Length];
            encData_byte = System.Text.Encoding.UTF8.GetBytes(rawPssword);
            string encodedData = Convert.ToBase64String(encData_byte);
            return encodedData;
        }
    }
}