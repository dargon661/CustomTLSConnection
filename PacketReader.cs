// In Client/PacketReader.cs
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace CustomTLSConnection
{
    // Inherit from BinaryReader to get useful methods like ReadByte()
    internal class PacketReader : BinaryReader
    {
        private readonly NetworkStream _networkStream;

        public PacketReader(NetworkStream input) : base(input)
        {
            _networkStream = input;
        }

        // This is the method that correctly reverses what PacketSender does.
        public override string ReadString()
        {
            // Step 1: Read the 4-byte integer length prefix.
            // This tells us how many bytes the string content will be.
            int length = ReadInt32();

            // Step 2: Create a buffer of that exact size.
            byte[] stringBytes = new byte[length];

            // Step 3: Read exactly that many bytes from the stream into the buffer.
            // This is critical. We read the content based on the length we just got.
            int bytesRead = 0;
            while (bytesRead < length)
            {
                // Loop to ensure all data is read, as a single network read might not get it all.
                bytesRead += _networkStream.Read(stringBytes, bytesRead, length - bytesRead);
            }

            // Step 4: Decode the bytes back into a string using the SAME encoding.
            return Encoding.ASCII.GetString(stringBytes);
        }
        public byte[] ReadBytes()
        {
            // 1. Read the 4-byte integer length prefix
            int bytesToRead = ReadInt32();

            // 2. Create a buffer of that exact size
            byte[] buffer = new byte[bytesToRead];
            int bytesRead = 0;

            // 3. Loop to ensure all data is read from the network
            while (bytesRead < bytesToRead)
            {
                int read = _networkStream.Read(buffer, bytesRead, bytesToRead - bytesRead);
                if (read == 0) throw new EndOfStreamException("Connection closed prematurely.");
                bytesRead += read;
            }
            return buffer;
        }
    }
}