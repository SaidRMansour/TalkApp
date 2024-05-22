using System;
using System.Security.Cryptography;

namespace GUI.Services
{
    public class EncryptionService
    {
        private readonly ECDiffieHellmanCng _diffieHellman;
        private byte[] _sharedKey;

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
            return _diffieHellman.PublicKey.ToByteArray();
        }

        public void GenerateSharedKey(byte[] otherPublicKey)
        {
            _sharedKey = _diffieHellman.DeriveKeyMaterial(CngKey.Import(otherPublicKey, CngKeyBlobFormat.EccPublicBlob));
        }

        public byte[] EncryptMessage(string message)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = _sharedKey;
                aes.IV = GenerateIV();

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

                byte[] hmac = GenerateHMAC(encryptedMessage, aes.IV);
                byte[] result = new byte[aes.IV.Length + hmac.Length + encryptedMessage.Length];
                Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
                Buffer.BlockCopy(hmac, 0, result, aes.IV.Length, hmac.Length);
                Buffer.BlockCopy(encryptedMessage, 0, result, aes.IV.Length + hmac.Length, encryptedMessage.Length);

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

        private byte[] GenerateIV()
        {
            using (Aes aes = Aes.Create())
            {
                aes.GenerateIV();
                return aes.IV;
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

        private bool VerifyHMAC(byte[] message, byte[] hmac, byte[] iv)
        {
            byte[] expectedHMAC = GenerateHMAC(message, iv);
            return CryptographicOperations.FixedTimeEquals(expectedHMAC, hmac);
        }
    }
}

