
using System.Security.Cryptography;
using System.Text;

namespace CustomTLSConnection.ClientSide
{
    internal static class RSAutil
    {
        public static byte[] EncryptString(string publicKey, string dataToEncrypt)
        {
            //using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(publicKey);
                byte[] messageBytes = Encoding.UTF8.GetBytes(dataToEncrypt);
                byte[] encryptedBytes = rsa.Encrypt(messageBytes, RSAEncryptionPadding.Pkcs1);
                return encryptedBytes;
            }
        }
        public static byte[] EncryptBytes(string publicKey, byte[] dataToEncrypt)
        {
            //using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            using (RSA rsa = RSA.Create())
            {

                rsa.FromXmlString(publicKey);

                byte[] messageBytes = dataToEncrypt;

                byte[] encryptedBytes = rsa.Encrypt(messageBytes, RSAEncryptionPadding.Pkcs1);
                return encryptedBytes;
            }
        }
        public static bool Verify(string publicKey, byte[] originalData, byte[] signature)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            //using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(publicKey);
               
                return rsa.VerifyData(originalData, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
    }
}
