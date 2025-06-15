

using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace CustomTLSConnection
{
    public static class ClientAESutil
    {
        private static byte[] AESkey;
        
        internal static void GenerateKey()
        {
            if (AESkey == null)
            {
                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256; // Strongest option
                    aes.GenerateKey();
                    AESkey=aes.Key;
                    aes.GenerateIV();

                    // Convert to Base64 for readable printing or sending over network
                    string keyBase64 = Convert.ToBase64String(AESkey);
                    string ivBase64 = Convert.ToBase64String(aes.IV);

                    
                }
            }
        }
        internal static void SendKeyToServer(TcpClient socket)
        {
            PacketSender KeySender = new PacketSender();
            KeySender.OpCode(4); // Define 1 as the opcode for sending a public key
            KeySender.WriteBytes(AESkey);

            socket.Client.Send(KeySender.ToByteArray());
        }


        public static byte[] Encrypt(string plainText)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = AESkey;
                aes.GenerateIV();

                using (MemoryStream ms = new MemoryStream())
                {
                    // Write the IV at the beginning of the stream
                    ms.Write(aes.IV, 0, aes.IV.Length);

                    using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] textBytes = Encoding.UTF8.GetBytes(plainText);
                        cs.Write(textBytes, 0, textBytes.Length);
                        cs.FlushFinalBlock();
                    }

                    // Return the combined IV + ciphertext
                    return ms.ToArray();
                }
            }
        }
        public static string Decrypt(byte[] encryptedData)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = AESkey;

                // Extract the IV (first 16 bytes)
                byte[] iv = new byte[16];
                Array.Copy(encryptedData, 0, iv, 0, iv.Length);
                aes.IV = iv;

                // The rest is the ciphertext
                int ciphertextStart = iv.Length;
                int ciphertextLength = encryptedData.Length - ciphertextStart;

                using (MemoryStream ms = new MemoryStream(encryptedData, ciphertextStart, ciphertextLength))
                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (StreamReader sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd(); // Decrypted string
                }
            }
        }


    }
}
