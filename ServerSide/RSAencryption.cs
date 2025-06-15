
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
namespace CustomTLSConnection.ServerSide
{
    internal static class RSAencryption
    {
        public static (string, string) GeneratePairKeys()
        {
            using (RSA rsa = RSA.Create())
            {
                string publicKey = rsa.ToXmlString(false);
                string privateKey = rsa.ToXmlString(true);

                return (publicKey, privateKey);
            }
        }

        public static byte[] Encrypt(string publicKey, string dataToEncrypt)
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

        public static string DecryptReturnString(string privateKey, byte[] encryptedBytes)
        {
            //using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(privateKey);
                byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
                string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);
                return decryptedMessage;
            }
        }
        public static byte[] DecryptReturnByte(string privateKey, byte[] encryptedBytes)
        {
            //using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(privateKey);
                byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
                
                return decryptedBytes;
            }
        }
        public static byte[] SignString(string privateKey, string dataToSign)
        {
            //using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(privateKey);
                byte[] messageBytes = Encoding.UTF8.GetBytes(dataToSign);
                byte[] signatureBytes = rsa.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return signatureBytes;
            }
        }
        public static byte[] SignBytes(string privateKey, byte[] messageBytes)
        {
            //using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(privateKey);
                
                byte[] signatureBytes = rsa.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return signatureBytes;
            }
        }

    }
}
