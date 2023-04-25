using System.Security.Cryptography;
using System.Text;

Console.WriteLine("\a");

string textToShow = @$"enter Char for ur function to use
1 - for Aes
2 - for Rsa
3 - for Des";
Console.WriteLine(textToShow);

int x = int.Parse(Console.ReadLine());

Console.WriteLine("");
for (int i = 0; i < 4; i++)
{
    Console.Write("\a");
    Console.Write(".");
    Thread.Sleep(500);

}

Console.WriteLine("\a");


/// <summary>
/// 
/// ////////////////////////////     test 
/// </summary>

Console.Clear();
switch (x)
{
    case 1:
        AesFunction();
        break;
        
    case 2:
        RsaFunction();
        break;
        
    case 3:
        DesFunction();
        break;

    default:
        Console.WriteLine("InValid number");
        break;
}

//AesFunction();
//RsaFunction();
//DesFunction();


#region Encrypt With Aes




static void AesFunction()
{


    Console.Write("\t\t\t\t");
    Console.BackgroundColor = ConsoleColor.Green;
    Console.ForegroundColor = ConsoleColor.Black;
    Console.WriteLine("=========      Encrypt With Aes    ==================\n\n");
    Console.BackgroundColor = ConsoleColor.Black;
    Console.ForegroundColor = ConsoleColor.White;

    Console.Write("Enter ur plain text: ");
    string original = Console.ReadLine();
    //string original = "iam mahmoud labeb";

    // Create a new instance of the Aes
    // class.  This generates a new key and initialization
    // vector (IV).
    using (Aes myAes = Aes.Create())
    {

        // Encrypt the string to an array of bytes.
        byte[] encrypted = EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);

        // Decrypt the bytes to a string.
        string roundtrip = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);

        //Display the original data and the decrypted data.
        Console.WriteLine("Original:   {0}", original);
        foreach (var item in encrypted)
        {
            Console.Write($"{item}");

        }
        Console.WriteLine();
        Console.WriteLine("Round Trip: {0}", roundtrip);
    }
}

static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
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

static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
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

#endregion



#region Encrypt With Rsa



static void RsaFunction()
{



    Console.Write("\t\t\t\t");
    Console.BackgroundColor = ConsoleColor.Red;
    Console.ForegroundColor = ConsoleColor.Black;
    Console.WriteLine("=========      Encrypt With Rsa    ==================\n\n");
    Console.BackgroundColor = ConsoleColor.Black;
    Console.ForegroundColor = ConsoleColor.White;



    var cryptoServiceProvider = new RSACryptoServiceProvider(2048); //2048 - Długość klucza
    var privateKey = cryptoServiceProvider.ExportParameters(true); //Generowanie klucza prywatnego
    var publicKey = cryptoServiceProvider.ExportParameters(false); //Generowanie klucza publiczny

    string publicKeyString = GetKeyString(publicKey);
    string privateKeyString = GetKeyString(privateKey);


    string textToEncrypt = GenerateTestString();
    Console.WriteLine("plain text: ");
    Console.WriteLine(textToEncrypt);
    Console.WriteLine("-------------------------------------------");

    string encryptedText = Encrypt(textToEncrypt, publicKeyString); //Szyfrowanie za pomocą klucza publicznego
    Console.WriteLine("encrypted text: ");
    Console.WriteLine(encryptedText);
    Console.WriteLine("-------------------------------------------");

    string decryptedText = Decrypt(encryptedText, privateKeyString); //Odszyfrowywanie za pomocą klucza prywatnego

    Console.WriteLine("plain text after decrypt: ");
    Console.WriteLine(decryptedText);
}

static string GetKeyString(RSAParameters publicKey)
{

    var stringWriter = new System.IO.StringWriter();
    var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
    xmlSerializer.Serialize(stringWriter, publicKey);
    return stringWriter.ToString();
}

static string Encrypt(string textToEncrypt, string publicKeyString)
{
    var bytesToEncrypt = Encoding.UTF8.GetBytes(textToEncrypt);

    using (var rsa = new RSACryptoServiceProvider(2048))
    {
        try
        {
            rsa.FromXmlString(publicKeyString.ToString());
            var encryptedData = rsa.Encrypt(bytesToEncrypt, true);
            var base64Encrypted = Convert.ToBase64String(encryptedData);
            return base64Encrypted;
        }
        finally
        {
            rsa.PersistKeyInCsp = false;
        }
    }
}

static string Decrypt(string textToDecrypt, string privateKeyString)
{
    var bytesToDescrypt = Encoding.UTF8.GetBytes(textToDecrypt);

    using (var rsa = new RSACryptoServiceProvider(2048))
    {
        try
        {

            // server decrypting data with private key                    
            rsa.FromXmlString(privateKeyString);

            var resultBytes = Convert.FromBase64String(textToDecrypt);
            var decryptedBytes = rsa.Decrypt(resultBytes, true);
            var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
            return decryptedData.ToString();
        }
        finally
        {
            rsa.PersistKeyInCsp = false;
        }
    }
}

static string GenerateTestString()
{
    //Guid opportinityId = Guid.NewGuid();
    //Guid systemUserId = Guid.NewGuid();
    //string currentTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

    //StringBuilder sb = new StringBuilder();
    //sb.AppendFormat("opportunityid={0}", opportinityId.ToString());
    //sb.AppendFormat("&systemuserid={0}", systemUserId.ToString());
    //sb.AppendFormat("&currenttime={0}", currentTime);
    /////////////////////////////////
    string sb = "iam mahmoud labeb";

    return sb.ToString();
}


#endregion



#region Encrypt With Des



static void DesFunction()
{



    Console.Write("\t\t\t\t");
    Console.BackgroundColor = ConsoleColor.Yellow;
    Console.ForegroundColor = ConsoleColor.Black;
    Console.WriteLine("=========      Encrypt With Des    ==================\n\n");
    Console.BackgroundColor = ConsoleColor.Black;
    Console.ForegroundColor = ConsoleColor.White;


    try
    {
        byte[] key;
        byte[] iv;

        // Create a new DES object to generate a random key
        // and initialization vector (IV).
        using (DES des = DES.Create())
        {
            key = des.Key;
            iv = des.IV;
        }

        // Create a string to encrypt.
        string original = "iam mahmoud labeb";
        Console.WriteLine($"plain text : {original}");
        // The name/path of the file to write.
        string filename = "CText.enc";

        // Encrypt the string to a file.
        EncryptTextToFile(original, filename, key, iv);

        // Decrypt the file back to a string.
        string decrypted = DecryptTextFromFile(filename, key, iv);

        // Display the decrypted string to the console.
        Console.WriteLine($"plain text after decrypted : {decrypted}");
    }
    catch (Exception e)
    {
        Console.WriteLine(e.Message);
    }
}


static void EncryptTextToFile(string text, string path, byte[] key, byte[] iv)
{
    try
    {
        // Create or open the specified file.
        using (FileStream fStream = File.Open(path, FileMode.Create))
        // Create a new DES object.
        using (DES des = DES.Create())
        // Create a DES encryptor from the key and IV
        using (ICryptoTransform encryptor = des.CreateEncryptor(key, iv))
        // Create a CryptoStream using the FileStream and encryptor
        using (var cStream = new CryptoStream(fStream, encryptor, CryptoStreamMode.Write))
        {
            // Convert the provided string to a byte array.
            byte[] toEncrypt = Encoding.UTF8.GetBytes(text);

            // Write the byte array to the crypto stream.
            cStream.Write(toEncrypt, 0, toEncrypt.Length);
        }
    }
    catch (CryptographicException e)
    {
        Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
        throw;
    }
}

static string DecryptTextFromFile(string path, byte[] key, byte[] iv)
{
    try
    {
        // Open the specified file
        using (FileStream fStream = File.OpenRead(path))
        // Create a new DES object.
        using (DES des = DES.Create())
        // Create a DES decryptor from the key and IV
        using (ICryptoTransform decryptor = des.CreateDecryptor(key, iv))
        // Create a CryptoStream using the FileStream and decryptor
        using (var cStream = new CryptoStream(fStream, decryptor, CryptoStreamMode.Read))
        // Create a StreamReader to turn the bytes back into text
        using (StreamReader reader = new StreamReader(cStream, Encoding.UTF8))
        {
            // Read back all of the text from the StreamReader, which receives
            // the decrypted bytes from the CryptoStream, which receives the
            // encrypted bytes from the FileStream.
            return reader.ReadToEnd();
        }
    }
    catch (CryptographicException e)
    {
        Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
        throw;
    }
}



#endregion





