using System;
using System.IO;
using System.Security.Cryptography;

namespace GUI.Services
{
    public class EncryptionService
    {
        private readonly ECDiffieHellmanCng _diffieHellman;
        private byte[] _sharedKey;
        private byte[] _iv;
        private byte[] _hmac;

        public EncryptionService()
        {
            _diffieHellman = new ECDiffieHellmanCng
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256
            };
        }

        public byte[] GetPublicKey()
        {
            return _diffieHellman.PublicKey.ExportSubjectPublicKeyInfo();
        }

        public void GenerateSharedKey(byte[] otherPublicKey)
        {
            using (var otherPartyKey = CngKey.Import(otherPublicKey, CngKeyBlobFormat.EccPublicBlob))
            {
                _sharedKey = _diffieHellman.DeriveKeyMaterial(otherPartyKey);
            }
            using (var sha256 = SHA256.Create())
            {
                _sharedKey = sha256.ComputeHash(_sharedKey);
            }

            // Convert the byte array to a readable string (Base64)
            string sharedKeyBase64 = Convert.ToBase64String(_sharedKey);
            Console.WriteLine("Shared key (Base64): " + sharedKeyBase64);

            // Convert the byte array to a readable string (Hexadecimal)
            string sharedKeyHex = BitConverter.ToString(_sharedKey).Replace("-", "");
            Console.WriteLine("Shared key (Hex): " + sharedKeyHex);
        }

        public byte[] GetIV()
        {
            return _iv;
        }

        public byte[] GetHMAC()
        {
            return _hmac;
        }

        public byte[] EncryptMessage(string message)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = _sharedKey;
                aes.GenerateIV();
                _iv = aes.IV; // Gem IV for senere brug

                byte[] encryptedMessage;
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(message);
                        }
                        encryptedMessage = msEncrypt.ToArray();
                    }
                }

                _hmac = GenerateHMAC(encryptedMessage, _iv); // Generer og gem HMAC for senere brug
                byte[] result = new byte[_iv.Length + _hmac.Length + encryptedMessage.Length];
                Buffer.BlockCopy(_iv, 0, result, 0, _iv.Length);
                Buffer.BlockCopy(_hmac, 0, result, _iv.Length, _hmac.Length);
                Buffer.BlockCopy(encryptedMessage, 0, result, _iv.Length + _hmac.Length, encryptedMessage.Length);

                return result;
            }
        }

        public string DecryptMessage(byte[] encryptedMessage)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = _sharedKey;

                byte[] iv = new byte[16];
                byte[] hmac = new byte[32];
                byte[] cipherText = new byte[encryptedMessage.Length - iv.Length - hmac.Length];

                Buffer.BlockCopy(encryptedMessage, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(encryptedMessage, iv.Length, hmac, 0, hmac.Length);
                Buffer.BlockCopy(encryptedMessage, iv.Length + hmac.Length, cipherText, 0, cipherText.Length);

                if (!VerifyHMAC(cipherText, hmac, iv))
                {
                    throw new CryptographicException("HMAC validering fejlet.");
                }

                aes.IV = iv;
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        private byte[] GenerateHMAC(byte[] message, byte[] iv)
        {
            using (HMACSHA256 hmac = new HMACSHA256(_sharedKey))
            {
                byte[] combined = new byte[iv.Length + message.Length];
                Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
                Buffer.BlockCopy(message, 0, combined, iv.Length, message.Length);
                return hmac.ComputeHash(combined);
            }
        }

        public bool VerifyHMAC(byte[] message, byte[] hmac, byte[] iv)
        {
            byte[] expectedHMAC = GenerateHMAC(message, iv);
            return CryptographicOperations.FixedTimeEquals(expectedHMAC, hmac);
        }
    }
}
