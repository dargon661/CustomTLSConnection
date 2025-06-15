
using CustomTLSConnection.EncryptionService;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace CustomTLSConnection.ServerSide
{
    public class CustomTLS
    {
        private TcpClient socket { get; set; }
        private PacketReader packetReader { get; set; }


        private string publicKey;
        private string privateKey;


        public CustomTLS(TcpClient socket)
        {
            this.socket = socket;

            (publicKey, privateKey) = RSAencryption.GeneratePairKeys();

        }

        public bool StartTLS()
        {
           SendPublicKey();
          byte[] decryptedMessage= GetRandomData();
            SendSignature(decryptedMessage);
            ServerAESutil.GetKey(socket);

            ValidateKey();
            return true;

        }

        private void ValidateKey()
        {
            byte[] ValidateMessage = ServerAESutil.Encrypt("Success");
            PacketSender sender = new PacketSender();
            sender.WriteBytes(ValidateMessage);
            socket.Client.Send(sender.ToByteArray());
        }

        private void SendPublicKey()
        {

            PacketSender PublicKeySender = new PacketSender();
            PublicKeySender.OpCode(1); // Define 1 as the opcode for sending a public key
            PublicKeySender.WriteString(publicKey);

            socket.Client.Send(PublicKeySender.ToByteArray());

            


        }
        private byte[] GetRandomData() // Renamed for clarity
        {
            try
            {
                var reader = new PacketReader(socket.GetStream());
                var opCode = reader.ReadByte();

                if (opCode == 2)
                {
                    // ---- THE FIX ----
                    // 1. Read the raw encrypted bytes using ReadBytes()
                    byte[] encryptedDataFromClient = reader.ReadBytes();
                    Console.WriteLine($"Server: Received {encryptedDataFromClient.Length} encrypted bytes.");

                    // 2. Decrypt the byte array directly
                    byte[] decryptedMessage = RSAencryption.DecryptReturnByte(privateKey, encryptedDataFromClient);
                    // -----------------

                    Console.WriteLine($"Server: Decrypted message successfully!");
                    // You can now compare the decrypted random data to what you expect,
                    // or use it as a session key, etc.

                    return decryptedMessage;
                }
                else
                {
                    Console.WriteLine("Unexpected opcode received.");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling encrypted data: {ex.Message}");
                throw;
            }
        }

        private void SendSignature(byte [] decryptedMessage)
        {
            byte[] signedData=RSAencryption.SignBytes(privateKey, decryptedMessage);
            var sendSignature = new PacketSender();
            sendSignature.OpCode(3);

            // ---- THE FIX ----
            // DO NOT use WriteString. Use WriteBytes for binary data.
            sendSignature.WriteBytes(signedData);
            // -----------------

            socket.Client.Send(sendSignature.ToByteArray());
        }
        
    }
}
