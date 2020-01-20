using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoApp
{
    class Program
    {
        static CspParameters cspp = new CspParameters();
        const string KeyFolder = @"c:\RSA\Keys\";
        const string EncFolder = @"c:\RSA\Encrypt\";
        const string DecFolder = @"c:\RSA\Decrypt\";

        static void Main(string[] args)
        {
            //var (publicKey, privateKey) = GenerateKeys(2048);
            //storeKeys("MyFirstKey", publicKey, privateKey);

            var publicKey = getPublicKey("MyFirstKey");
            var privateKey = getPrivateKey("MyFirstKey");

            string data = "Hej hopp alla glada";
            var byteData = Encoding.ASCII.GetBytes(data);
            var encryptedData = RSAEncrypt(byteData, publicKey);
            var decryptedData = RSADecrypt(encryptedData, privateKey);
            var plainText = Encoding.ASCII.GetString(decryptedData);
            Console.WriteLine(plainText);
        }

        static void useAes()
        {
            var key = GetRandomData(256 / 8);
            string data = "Hej hopp alla glada";
            var byteData = Encoding.ASCII.GetBytes(data);
            var encryptedData = Encrypt(byteData, key, out byte[] iv);

            var decryptedData = Decrypt(encryptedData, key, iv);
            var plaintext = Encoding.ASCII.GetString(decryptedData);
            Console.WriteLine(plaintext);
        }
        /****************************************************
         * Util
         ****************************************************/
        private static byte[] GetRandomData(int length)
        {
            using(var rngCsp = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                var randomData = new byte[length];
                rngCsp.GetBytes(randomData);
                return randomData;
            }
        }

        /****************************************************
         * RSA
         ****************************************************/
        static void storeKeys(string keyName, RSAParameters publicKey, RSAParameters privateKey)
        {
            cspp.KeyContainerName = keyName;
            var rsa = new RSACryptoServiceProvider(cspp)
            {
                PersistKeyInCsp = true
            };


            // Store public key in a txt file
            Directory.CreateDirectory(KeyFolder);
            StreamWriter sw = new StreamWriter(KeyFolder + keyName + ".txt");
            sw.Write(rsa.ToXmlString(false));
            sw.Close();
        }

        static RSAParameters getPublicKey(string keyName)
        {
            StreamReader sr = new StreamReader(KeyFolder + keyName + ".txt");
            cspp.KeyContainerName = keyName;
            string keyTxt = sr.ReadToEnd();
            var rsa = new RSACryptoServiceProvider(cspp);
            rsa.FromXmlString(keyTxt);
            rsa.PersistKeyInCsp = true;
            sr.Close();
            return rsa.ExportParameters(includePrivateParameters: false);
        }

        static RSAParameters getPrivateKey(string keyName)
        {
            cspp.KeyContainerName = keyName;
            var rsa = new RSACryptoServiceProvider(cspp);
            return rsa.ExportParameters(includePrivateParameters: true);
        }
        
        static (RSAParameters publicKey, RSAParameters privateKey) GenerateKeys(int keyLength)
        {
            using(var rsa = RSA.Create())
            {
                rsa.KeySize = keyLength;
                return (
                    publicKey: rsa.ExportParameters(includePrivateParameters: false),
                    privateKey: rsa.ExportParameters(includePrivateParameters: true)
                    );
            }
        }

        private static byte[] RSAEncrypt(byte[] data, RSAParameters publicKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);
                return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            }
        }
        private static byte[] RSADecrypt(byte[] data, RSAParameters privateKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);
                return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
            }
        }



        /****************************************************
         * AES
         ****************************************************/
        static byte[] Encrypt(byte[] data, byte[] key, out byte[] iv)
        {
            using(var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Key = key;
                aes.GenerateIV();

                using( var transform = aes.CreateEncryptor())
                {
                    iv = aes.IV;
                    return transform.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            using(var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                using (var transform = aes.CreateDecryptor())
                {
                    return transform.TransformFinalBlock(data, 0, data.Length);
                }

            }
        }
    }
}
