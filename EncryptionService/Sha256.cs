using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CustomTLSConnection.EncryptionService
{
    public static class Sha256
    {
        public static string ConvertPasswordToSha256(string password)
        {
            using(SHA256 sha256 =SHA256.Create())
            {
                byte[] hashedPassword=sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                Console.WriteLine(Convert.ToBase64String(hashedPassword));
                return Convert.ToBase64String(hashedPassword);

            }
        }
    }
}
