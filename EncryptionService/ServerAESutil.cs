

using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace CustomTLSConnection.EncryptionService
{
    public class ServerAESutil
    {
        private static byte[] AESkey;

        internal static void GetKey(TcpClient socket)
        {
            try
            {
                var reader = new PacketReader(socket.GetStream());
                var opCode = reader.ReadByte();

                if (opCode == 4)
                {
                    byte[] key = reader.ReadBytes();
                    AESkey = key;
                    Console.WriteLine("GotTheKey");
                }
                else
                {
                    Console.WriteLine("Unexpected opcode received.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling key: {ex.Message}");
                throw;
            }
            
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
