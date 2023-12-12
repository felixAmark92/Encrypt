using System.IO;
using System.Net;
using System.Security.AccessControl;
using System.Text;

namespace AES;

internal class Program
{
    private static List<string> Directories { get; set; } =  new List<string>();
    private static string WorkingDir { get; set; } = Directory.GetCurrentDirectory();
    public static void Main(string[] args)
    {
        var iv = new byte[16] { 3, 54, 123, 12, 46, 200, 123, 12, 42, 129, 162, 123, 42, 153, 123, 51 };

        Directories = Directory.GetDirectories(WorkingDir, "*", SearchOption.AllDirectories).Reverse().ToList();


        if (args.Length <= 0)
        {
            Console.WriteLine("type -h to show available commands");
        }
        else switch (args[0])
        {
            case "encrypt":
            {
                Console.Write("Enter key: ");
                var input = ReadLineHidden();

                Console.Write("Enter key again: ");
                var input2 = ReadLineHidden();

                if (input != input2)
                {
                    Console.WriteLine("key entered is not the same");
                    return;
                }

                var key = Cryptography.CreateSha256Hash(input);

                Console.WriteLine("Encrypting directory...");
                foreach (var directory in Directories)
                {
                    EncryptFiles(key, directory);
                }
                EncryptFiles(key, WorkingDir);
                EncryptDirectories(key, Directories.ToArray());

                Console.WriteLine("directory has been encrypted");
                break;
            }
            case "decrypt":
            {
                Console.Write("Enter key: ");
                var input = ReadLineHidden();

                var key = Cryptography.CreateSha256Hash(input);

                Console.WriteLine("Decrypting directory...");
                foreach (var directory in Directories)
                {
                    DecryptFiles(key, directory);
                }
                DecryptFiles(key, WorkingDir);
                DecryptDirectories(key, Directories.ToArray());
                Console.WriteLine("files have been decrypted");
                break;
            }
            case "files":
                foreach (var directory in Directories)
                {
                    var files = Directory.GetFiles(directory);

                    foreach (var file in files)
                    {
                        Console.WriteLine(file);
                    }
                }
                break;
            case "dir":
                Console.WriteLine("working directory: " + Directory.GetCurrentDirectory());
                break;
            default:
                Console.WriteLine("invalid command");
                break;
        }
    }

    static void EncryptFiles( byte[] key, string path)
    {
        var directoryInfo = new DirectoryInfo(path);
        var files = directoryInfo.GetFiles().Where(f => !f.Attributes.HasFlag(FileAttributes.Hidden));


        int i = 0;
        foreach (var file in files)
        {
            
            var attr = File.GetAttributes(file.FullName);

            if ((attr & FileAttributes.ReadOnly) != 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Can't encypt read-only file {file.FullName}. File skipped");
                Console.ResetColor();
                continue;
            }
            Console.WriteLine($"Encrypting file: {file.FullName}");



            var iv = Cryptography.GenerateIV();

            var fileBytes = File.ReadAllBytes(file.FullName);

            var encryption = Cryptography.EncryptBytesToBytes_Aes(fileBytes, key, iv);

            var fileNameEncrypted = Cryptography.EncryptStringToBytes_Aes(file.Name, key, iv);
            

            File.WriteAllBytes(file.FullName, encryption);
            File.Move(file.FullName, Path.Combine(path, i.ToString()));

            var ivFile = Path.Combine(path, i + ".iv");
            var fileNameFile = Path.Combine(path, i + ".fn");

            File.WriteAllBytes(ivFile, iv);
            File.SetAttributes(ivFile, FileAttributes.Hidden);
            
            File.WriteAllBytes(fileNameFile, fileNameEncrypted);
            File.SetAttributes(fileNameFile, FileAttributes.Hidden);

            i++;
        }
    }
    static void DecryptFiles(byte[] key, string path)
    {
        var directoryInfo = new DirectoryInfo(path);
        var files = directoryInfo.GetFiles().Where(f => !f.Attributes.HasFlag(FileAttributes.Hidden));

        foreach (var file in files)
        {

            var attr = File.GetAttributes(file.FullName);

            if ((attr & FileAttributes.ReadOnly) != 0)
            {
                continue;
            }
            Console.WriteLine($"Decrypting file {file.FullName}");
            
            var ivFile = directoryInfo.GetFiles().Single(f => f.Name == file.Name + ".iv");
            var fileNameFile = directoryInfo.GetFiles().Single(f => f.Name == file.Name + ".fn");

            var fileNameEncrypted = File.ReadAllBytes(fileNameFile.FullName);
            var iv = File.ReadAllBytes(ivFile.FullName);

            var fileBytes = File.ReadAllBytes(file.FullName);

            var decryption = Cryptography.DecryptBytesFromBytes_Aes(fileBytes, key, iv);
            var fileNameDecrypted = Cryptography.DecryptBytesFromBytes_Aes(fileNameEncrypted, key, iv);

            File.WriteAllBytes(file.FullName, decryption);
            File.Move(file.FullName, Path.Combine(path, Encoding.Default.GetString(fileNameDecrypted)));

            File.Delete(ivFile.FullName);
            File.Delete(fileNameFile.FullName);
        }
    }
    static void EncryptDirectories(byte[] key, string[] directories)
    {

        int i = 0;
        foreach (var directory in directories)
        {
            var dirInfo = new DirectoryInfo(directory);

            var iv = Cryptography.GenerateIV();

            var directoryName = dirInfo.Name;

            var directoryNameEncrypted = Cryptography.EncryptStringToBytes_Aes(directoryName, key, iv);

            string parent = new DirectoryInfo(directory).Parent.FullName;

            string finalPath = Path.Combine(parent, i + "d");

            Directory.Move(directory, finalPath);

            var ivFile = Path.Combine(dirInfo.Parent.FullName, i + "d" + ".iv");
            var DirectoryNameFile = Path.Combine(dirInfo.Parent.FullName, i + "d" + ".dn");

            File.WriteAllBytes(ivFile, iv);
            File.SetAttributes(ivFile, FileAttributes.Hidden);
            
            File.WriteAllBytes(DirectoryNameFile, directoryNameEncrypted);
            File.SetAttributes(DirectoryNameFile, FileAttributes.Hidden);

            i++;

        }
    }
    static void DecryptDirectories(byte[] key, string[] directories)
    {

        foreach (var directory in directories)
        {
            var dirInfo = new DirectoryInfo(directory);
            
            var ivFile = dirInfo.Parent.GetFiles().Single(f => f.Name == dirInfo.Name + ".iv");
            var iv = File.ReadAllBytes(ivFile.FullName);
            
            var directoryNameFile = dirInfo.Parent.GetFiles().Single(f => f.Name == dirInfo.Name + ".dn");
            var directoryName = File.ReadAllBytes(directoryNameFile.FullName);

            var directoryNameDecrypted = Cryptography.DecryptStringFromBytes_Aes(directoryName, key, iv);

            string parent = new DirectoryInfo(directory).Parent.FullName;

            string finalPath = Path.Combine(parent, directoryNameDecrypted);

            Directory.Move(directory, finalPath);

            File.Delete(ivFile.FullName);
            File.Delete(directoryNameFile.FullName);

        }
    }



    static string ReadLineHidden()
    {
        int cursorStart = Console.CursorLeft;
        var stringBuilder = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo keyInfo = Console.ReadKey();

            if (keyInfo.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return stringBuilder.ToString();
            }
            if (keyInfo.Key == ConsoleKey.Backspace && stringBuilder.Length + cursorStart > cursorStart)
            {
                stringBuilder.Remove(stringBuilder.Length - 1, 1);
                Console.Write(' ');

                Console.CursorLeft--;
            }
            if (keyInfo.Key == ConsoleKey.Backspace && Console.CursorLeft < cursorStart)
            {
                Console.CursorLeft++;
            }

            if (!char.IsControl(keyInfo.KeyChar))
            {
                stringBuilder.Append(keyInfo.KeyChar);
                Console.CursorLeft--;
                Console.Write('*');
            }
        }
    }
}