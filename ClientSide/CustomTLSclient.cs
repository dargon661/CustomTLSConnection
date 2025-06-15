

using System.Net.Sockets;
using System.Security.Cryptography;




namespace CustomTLSConnection.ClientSide
{
    public class CustomTLSclient
    {
        private TcpClient client;
        private string publicKey;
        public CustomTLSclient(TcpClient client)
        {
            this.client = client;
        }
        public bool StartTLS()
        {
            ReceivePublicKey();

            byte[] challenge =CreateRandomData();

            GetSignature(challenge);

            ClientAESutil.GenerateKey();
            ClientAESutil.SendKeyToServer(client);


            bool IsKeySent=ValidateKey();
            if(IsKeySent)
                Console.WriteLine("true");
            else
                Console.WriteLine("false"); 
            return IsKeySent;
        }

        private bool ValidateKey()
        {
            var reader = new PacketReader(client.GetStream());
            byte[] validateMessage = reader.ReadBytes();
            if(ClientAESutil.Decrypt(validateMessage).Equals("Success"))
            {
                return true;
            }
            return false;
        }

        private void SendKey()
        {
            
        }

        private void ReceivePublicKey()
        {
            try
            {
                var publicKeyReader = new PacketReader(client.GetStream());

                // THIS IS A BLOCKING CALL
                // The program will PAUSE on this line and wait. The thread
                // executing this code cannot do anything else until a byte
                // of data arrives from the server.
                var opCode = publicKeyReader.ReadByte();

                if (opCode == 1)
                {
                    // This is also a blocking call
                    publicKey = publicKeyReader.ReadString();
                    Console.WriteLine($"Public key received: {publicKey}");
                }
                else
                {
                    Console.WriteLine("Unexpected opcode received.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error receiving public key: {ex.Message}");
                // It's good practice to re-throw if you can't handle it,
                // so the caller knows something went wrong.
                throw;
            }
        }


        private byte [] CreateRandomData()
        {
            // 1. Create random data (this is correct)
            byte[] randomChallenge = new byte[64];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomChallenge);
            }

            // 2. Encrypt the bytes (this is correct)
            byte[] encryptedData = RSAutil.EncryptBytes(publicKey, randomChallenge);

            // 3. Send the encrypted bytes using the CORRECT method
            var sendRandomData = new PacketSender();
            sendRandomData.OpCode(2);

            // ---- THE FIX ----
            // DO NOT use WriteString. Use WriteBytes for binary data.
            sendRandomData.WriteBytes(encryptedData);
            // -----------------

            client.Client.Send(sendRandomData.ToByteArray());
            return randomChallenge;
            
        }



        private void GetSignature(byte[] randomChallenge) 
        {
            try
            {
                var reader = new PacketReader(client.GetStream());
                var opCode = reader.ReadByte();

                if (opCode == 3)
                {

                    byte[] encryptedDataFromClient = reader.ReadBytes();
                    if(RSAutil.Verify(publicKey, randomChallenge, encryptedDataFromClient))
                    {
                        Console.WriteLine("signature validated. all good");
                    }
                    else
                    {
                        Console.WriteLine("man in the middle attack. connection closed");
                        client.Close();
                    }
                }

                else
                {
                    Console.WriteLine("Unexpected opcode received.");

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling encrypted data: {ex.Message}");
                throw;
            }
        }



        
    }
}
