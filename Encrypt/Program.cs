using WpfApp1;

var key = Cryptography.CreateSha256Hash("123");

var iv = new byte[16] { 3, 54, 123, 12, 46, 200, 123, 12, 42, 129, 162, 123, 42, 153, 123, 51 };

string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "Test");

var filesFullPath = Directory.GetFiles(path);



Decrypt(filesFullPath, key, iv, path);


void Encrypt(string[] filesFullPath2, byte[] key2, byte[] iv1, string path2)
{
    foreach (var file in filesFullPath2)
    {
        var fileName = Path.GetFileName(file);

        var filebytes = File.ReadAllBytes(file);

        var encryption = Cryptography.EncryptBytesToBytes_Aes(filebytes, key2, iv1);
        var fileNameEncrypted = Cryptography.EncryptStringToBytes_Aes(fileName, key2, iv1);

        var fileNameHex = Convert.ToHexString(fileNameEncrypted);

        File.WriteAllBytes(Path.Combine(path2, fileNameHex), encryption);
        File.Delete(file);
    }
}

void Decrypt(string[] strings, byte[] bytes, byte[] bytes1, string s)
{
    foreach (var file in strings)
    {
        var fileName = Path.GetFileName(file);

        var filebytes = File.ReadAllBytes(file);

        var decryption = Cryptography.DecryptBytesFromBytes_Aes(filebytes, bytes, bytes1);
        var fileNameDecrypted = Cryptography.DecryptStringFromBytes_Aes(Convert.FromHexString(fileName), bytes, bytes1);

        File.WriteAllBytes(Path.Combine(s, fileNameDecrypted), decryption);
        File.Delete(file);
    }
}