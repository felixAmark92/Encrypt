using System.Security.Cryptography;
using System.Text;

namespace AES;

public static class Cryptography
{

    public static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
    {
        // Check arguments.
        if (plainText == null || plainText.Length <= 0)
            throw new ArgumentNullException("plainText");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");
        byte[] encrypted;

        // Create an Aes object
        // with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        // Return the encrypted bytes from the memory stream.
        return encrypted;
    }

    public static byte[] EncryptBytesToBytes_Aes(byte[] plainBytes, byte[] Key, byte[] IV)
    {
        // Check arguments.
        if (plainBytes == null)
            throw new ArgumentNullException("plainBytes");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");
        byte[] encrypted;

        if (plainBytes.Length <= 0)
            return plainBytes;

        // Create an Aes object with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    // Write the byte[] data to the CryptoStream.
                    csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                    csEncrypt.FlushFinalBlock();
                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        // Return the encrypted bytes from the memory stream.
        return encrypted;
    }


    public static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
    {
        // Check arguments.
        if (cipherText == null || cipherText.Length <= 0)
            throw new ArgumentNullException("cipherText");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");

        // Declare the string used to hold
        // the decrypted text.
        string plaintext = null;

        // Create an Aes object
        // with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        return plaintext;
    }

    public static byte[] DecryptBytesFromBytes_Aes(byte[] cipherBytes, byte[] Key, byte[] IV)
    {
        // Check arguments.
        if (cipherBytes == null )
            throw new ArgumentNullException("cipherBytes");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");

        if (cipherBytes.Length <= 0)
            return cipherBytes;

        // Declare the byte array used to hold the decrypted data.
        byte[] decryptedBytes = null;

        // Create an Aes object with the specified key and IV.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (MemoryStream msOutput = new MemoryStream())
                    {
                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        while ((bytesRead = csDecrypt.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            msOutput.Write(buffer, 0, bytesRead);
                        }
                        decryptedBytes = msOutput.ToArray();
                    }
                }
            }
        }

        return decryptedBytes;
    }
    public static byte[] CreateSha256Hash(string inputString, byte[] salt)
    {
        HashAlgorithm algorithm = SHA256.Create();
        var result = GetHash(inputString, salt, algorithm);
        return result;
    }

    public static byte[] CreateSha256Hash(string inputString)
    {
        HashAlgorithm algorithm = SHA256.Create();
        var result = GetHash(inputString, algorithm);
        return result;
    }

    private static byte[] GetHash(string inputString, byte[] salt, HashAlgorithm algorithm)
    {
        byte[] inputBytes = Encoding.Default.GetBytes(inputString);
        byte[] saltedInputBytes = inputBytes.Concat(salt).ToArray();
        return algorithm.ComputeHash(saltedInputBytes);
    }
    private static byte[] GetHash(string inputString, HashAlgorithm algorithm)
    {
        byte[] inputBytes = Encoding.Default.GetBytes(inputString);
        return algorithm.ComputeHash(inputBytes);
    }
    public static byte[] GenerateSalt()
    {
        var random = RandomNumberGenerator.Create();
        var salt = new byte[32];

        random.GetNonZeroBytes(salt);
        return salt;
    }

    public static byte[] GenerateIV()
    {
        var random = RandomNumberGenerator.Create();
        var iv = new byte[16];

        random.GetNonZeroBytes(iv);
        return iv;
    }
}