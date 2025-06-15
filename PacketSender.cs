using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;

namespace CustomTLSConnection
{
    internal class PacketSender
    {
        MemoryStream memoryStream;

        public PacketSender()
        {
            this.memoryStream = new MemoryStream();
        }
        public void OpCode(byte opCode)
        {
            memoryStream.WriteByte(opCode);
        }
        public void WriteString(string str)
        {
            var length = str.Length;
            byte[] lengthBytes = BitConverter.GetBytes(length);
            byte[] stringBytes = Encoding.ASCII.GetBytes(str);

            memoryStream.Write(lengthBytes, 0, lengthBytes.Length);   // Write length
            memoryStream.Write(stringBytes, 0, stringBytes.Length);   // ✅ Write string content
        }
        public void WriteBytes(byte[] data)
        {
            int length = data.Length;
            // Write the 4-byte integer length to the stream
            memoryStream.Write(BitConverter.GetBytes(length), 0, sizeof(int));
            // Write the actual byte data itself
            memoryStream.Write(data, 0, length);
        }


        public byte[] ToByteArray()
        {
            return memoryStream.ToArray();
        }

    }
}
