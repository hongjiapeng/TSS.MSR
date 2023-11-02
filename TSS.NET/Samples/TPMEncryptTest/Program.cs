// See https://aka.ms/new-console-template for more information
using System.Text;
using Tpm2Lib;
{
    // Digest algorithm
    TpmAlgId tpmAlgId = TpmAlgId.Sha1;

    System.Console.WriteLine("Creating TPM device...");

    Tpm2Device tpmDevice = new TbsDevice();

    System.Console.WriteLine("Connecting TPM device...");

    tpmDevice.Connect(); // 1. Connect TPM

    System.Console.WriteLine("Creating TPM object...");

    var tpm = new Tpm2(tpmDevice);

    var cstr = "Hello World!"; // Define a string constant, which is the content to be encrypted

    byte[] data = Encoding.ASCII.GetBytes(cstr);

    // Password authorization, that is, identity authentication, here is the password, other methods can also be used, such as HMAC\Policy, etc.

    string cpwd = "password"; // Used for identity authentication, unrelated to encryption and decryption

    byte[] useAuth = Encoding.ASCII.GetBytes(cpwd);

    // The encryption and decryption methods must use the same Handle to complete the encryption and decryption,
    // otherwise if it is a different Handle, it points to different memory areas, that is, different keys

    TpmHandle keyHandle = null;

    System.Console.WriteLine("Encrypting...");

    // Then, we create an RSA key and use the public key of the RSA key to encrypt the data
    byte[] encrypedData = Encrypt(tpmAlgId, tpm, useAuth, data, ref keyHandle);


    // Finally, we use the private key of the RSA key to decrypt the data
    // byte[] decryptedData = Decrypt(tpm, useAuth, encrypedData, keyHandle);

    string encryptedString = BitConverter.ToString(encrypedData);
    // string decryptedString = BitConverter.ToString(decryptedData);
    string dataHexString = BitConverter.ToString(data);

    // Then output the plaintext data, encrypted data and decrypted data
    Console.WriteLine($"Raw data: {dataHexString}");

    Console.WriteLine($"Encrypted data: {encryptedString}");

    // Console.WriteLine($"Decrypted: {decryptedString}");

    string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

    string filePath = Path.Combine(desktopPath, "encrypt_data.dat");

    File.WriteAllBytes(filePath, encrypedData);

    Console.WriteLine($"Encryption data saved desktop successfully!");

    Console.WriteLine("Store data to nv successfully!");

    Console.WriteLine($"File saved path: {filePath}");

    Console.ReadLine();

    // Tpm2 is a Key template, which is a template for RSA keys. It can be simply understood that the template is a description of the key, and the key is the actual data
}


// We will create a pair of RSA keys, which include public and private keys
// In asymmetric keys, the typical encryption scenario is to use the public key to encrypt data and the private key to decrypt data. Of course, this operation can also be reversed, and if reversed, it is called a digital signature
// Because our example uses a public key to encrypt data, it is called asymmetric encryption
byte[] Encrypt(TpmAlgId tpmAlgId, Tpm2 tpm, byte[] useAuth, byte[] data, ref TpmHandle keyHandle)
{
    // ObjectAttr is a multi-value parameter, which represents the attributes of the key. Here it means that the key is decryptable, requires user authentication, is sensitive data, and is original data
    // SymDefObject is the parameter of the symmetric encryption algorithm. Here it means using the AES algorithm, the key length is 128 bits, and the mode is CFB
    System.Console.WriteLine("create tpm public");
    TpmPublic tpmPublic = new TpmPublic(
         tpmAlgId,
         ObjectAttr.Decrypt | ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin,
         null,
         new RsaParms(
             new SymDefObject(),
             new SchemeOaep(tpmAlgId),
             2048,
             65537),
         new Tpm2bPublicKeyRsa());

    System.Console.WriteLine("Creating sensitive data...");

    SensitiveCreate sensCreate = new SensitiveCreate(useAuth, null);

    System.Console.WriteLine("Creating key...");
    keyHandle = tpm.CreatePrimary(TpmRh.Null,
                                    sensCreate,
                                    tpmPublic,
                                    null,
                                    null,
                                    out TpmPublic keyPublic,
                                    out CreationData creationData,
                                    out byte[] creationHash,
                                    out TkCreation creationTicket);

    System.Console.WriteLine("Encrypting data...");
    // Encrypt plaintext data with public key
    byte[] encryptedData = keyPublic.EncryptOaep(data, null);

    System.Console.WriteLine("Data encrypted successfully!");
    return encryptedData;
}