using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace GUI.Services
{
    public class EncryptionService
    {
        private readonly ECDiffieHellman _diffieHellman;
        private byte[] _sharedKey;
        private byte[] _iv;
        private byte[] _hmac;
        private readonly IDataProtector _protector;

        // Initialiserer en ny instans af EncryptionService og genererer en Diffie-Hellman nøglepar
        public EncryptionService(IDataProtectionProvider provider)
        {
            _diffieHellman = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            _protector = provider.CreateProtector("PrivateKeyProtector");
        }

        // Initialiserer en ny instans af EncryptionService med en beskyttet privat nøgle
        public EncryptionService(IDataProtectionProvider provider, string protectedPrivateKey)
        {
            _protector = provider.CreateProtector("PrivateKeyProtector");
            var privateKeyBytes = _protector.Unprotect(Convert.FromBase64String(protectedPrivateKey));
            _diffieHellman = ECDiffieHellman.Create();
            _diffieHellman.ImportECPrivateKey(privateKeyBytes, out _);
        }

        // Henter og beskytter den private nøgle
        public string GetProtectedPrivateKey()
        {
            var privateKeyBytes = _diffieHellman.ExportECPrivateKey();
            return Convert.ToBase64String(_protector.Protect(privateKeyBytes));
        }

        // Henter den offentlige nøgle
        public byte[] GetPublicKey()
        {
            return _diffieHellman.ExportSubjectPublicKeyInfo();
        }

        // Genererer en delt nøgle baseret på en anden parts offentlige nøgle
        public void GenerateSharedKey(byte[] otherPublicKey)
        {
            try
            {
                var otherPartyPublicKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                otherPartyPublicKey.ImportSubjectPublicKeyInfo(otherPublicKey, out _);
                _sharedKey = _diffieHellman.DeriveKeyMaterial(otherPartyPublicKey.PublicKey);

                using (var sha256 = SHA256.Create())
                {
                    _sharedKey = sha256.ComputeHash(_sharedKey);
                }
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Kunne ikke generere delt nøgle.", ex);
            }
        }

        // Henter initialiseringsvektoren (IV)
        public byte[] GetIV()
        {
            return _iv;
        }

        // Henter HMAC
        public byte[] GetHMAC()
        {
            return _hmac;
        }

        // Krypterer en besked ved hjælp af AES
        public byte[] EncryptMessage(string message)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = _sharedKey;
                aes.GenerateIV();
                _iv = aes.IV;

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
                _hmac = GenerateHMAC(encryptedMessage, _iv);

                return encryptedMessage;
            }
        }

        // Dekrypterer en besked ved hjælp af AES og verificerer HMAC
        public string DecryptMessage(byte[] encryptedMessage, byte[] iv, byte[] hmac)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = _sharedKey;
                aes.IV = iv;

                // Verificerer HMAC for at sikre beskedens integritet
                if (!VerifyHMAC(encryptedMessage, hmac, iv))
                {
                    throw new CryptographicException("HMAC validering fejlet.");
                }

                using (MemoryStream msDecrypt = new MemoryStream(encryptedMessage))
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

        // Genererer en HMAC for en besked og initialiseringsvektoren (IV)
        private byte[] GenerateHMAC(byte[] message, byte[] iv)
        {
            using (HMACSHA256 hmac = new HMACSHA256(_sharedKey))
            {
                byte[] combined = new byte[iv.Length + message.Length];
                Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
                Buffer.BlockCopy(message, 0, combined, iv.Length, message.Length);
                var hmacValue = hmac.ComputeHash(combined);
                return hmacValue;
            }
        }

        // Verificerer HMAC for at sikre beskedens integritet
        public bool VerifyHMAC(byte[] message, byte[] hmac, byte[] iv)
        {
            byte[] expectedHMAC = GenerateHMAC(message, iv);
            return CryptographicOperations.FixedTimeEquals(expectedHMAC, hmac);
        }
    }
}
