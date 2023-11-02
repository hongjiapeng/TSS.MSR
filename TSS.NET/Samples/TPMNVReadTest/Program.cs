// See https://aka.ms/new-console-template for more information
using System.Text;
using Tpm2Lib;

{
    // Digest algorithm
    TpmAlgId hashAlg = TpmAlgId.Sha1;

    System.Console.WriteLine("Creating TPM device...");

    Tpm2Device tpmDevice = new TbsDevice();

    System.Console.WriteLine("Connecting TPM device...");

    tpmDevice.Connect(); // 1. Connect TPM

    System.Console.WriteLine("Creating TPM object...");

    var tpm = new Tpm2(tpmDevice);

    // 定义分层存储密码
    //string ownerpwd = "E(H + MbQe";

    //byte[] ownerAuth = Encoding.ASCII.GetBytes(ownerpwd);

    //var cstr = "Hello World!"; // Define a string constant, which is the content to be encrypted

    byte[] data = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 };

    // Password authorization, that is, identity authentication, here is the password, other methods can also be used, such as HMAC\Policy, etc.
    // nv index password
    string nvIndexPassword = "password2"; // Used for identity authentication, unrelated to encryption and decryption

    byte[] authValue = Encoding.ASCII.GetBytes(nvIndexPassword);

    // The encryption and decryption methods must use the same Handle to complete the encryption and decryption,
    // otherwise if it is a different Handle, it points to different memory areas, that is, different keys

    //System.Console.WriteLine("Encrypting...");

    //string dataHexString = BitConverter.ToString(data);

    // Then output the plaintext data, encrypted data and decrypted data
    //Console.WriteLine($"Raw data: {dataHexString}");

    // Console.WriteLine($"Decrypted: {decryptedString}");

    //tpm.OwnerAuth.AuthVal = ownerAuth;

    try
    {
        ushort nVSize = (ushort)data.Length;

        //byte[] nvRead = ReadDataFromNV(tpm, authValue, nVSize);
        byte[] nvRead = ReadDataFromNVWithPolicy(tpm, hashAlg, authValue, nVSize);

        string decryptedString = BitConverter.ToString(nvRead);

        Console.WriteLine($"Data read from nv - slot: {decryptedString}");

        Console.WriteLine("Read data to nv successfully!");
        //TpmHandle keyHandle = CreatePrimaryRsaKey(tpm, hashAlg, useAuth);

        //byte[] decryptedData = Decrypt(tpm, useAuth, nvRead, keyHandle);

        //Console.WriteLine($"decrypt data:{decryptedString}");

    }
    catch (Exception ex)
    {
        Console.WriteLine($"ReadDataFromNV Error Message:{ex.Message},InnerException:{ex.InnerException},StackTrace:{ex.StackTrace}");
    }

    Console.ReadLine();

    // Tpm2 is a Key template, which is a template for RSA keys. It can be simply understood that the template is a description of the key, and the key is the actual data
}

byte[] ReadDataFromNV(Tpm2 tpm, byte[] authValue, ushort size)
{
    try
    {
        TpmHandle nvHandle = TpmHandle.NV(5001);

        nvHandle.SetAuth(authValue);

        //AuthValue nvAuth = AuthValue.FromRandom(8);
        //tpm.NvDefineSpace(TpmRh.Owner, nvAuth,
        //                  new NvPublic(nvHandle, TpmAlgId.Sha1,
        //                               NvAttr.Authread | NvAttr.Authwrite,
        //                               null, size));

        byte[] nvRead = tpm.NvRead(nvHandle, nvHandle, size, 0);

        return nvRead;  

    }
    catch (System.Exception ex)
    {
        Console.WriteLine($"StoreDataToNV Error Message:{ex.Message},InnerException:{ex.InnerException},StackTrace:{ex.StackTrace}");
    }

    return default;
}

byte[] ReadDataFromNVWithPolicy(Tpm2 tpm, TpmAlgId hashAlg, byte[] authValue, ushort size)
{
    try
    {
        TpmHandle nvHandle = TpmHandle.NV(5001);

        //define policy
        PolicyTree policyTree = new PolicyTree(hashAlg);
        policyTree.Create(new PolicyAce[]
        {
            new TpmPolicyAuthValue(),
        });

        nvHandle.SetAuth(authValue);

        tpm.NvReadPublic(nvHandle, out byte[] nvName);

        nvHandle.SetName(nvName);

        AuthSession session = tpm.StartAuthSessionEx(TpmSe.Policy, hashAlg);

        session.RunPolicy(tpm, policyTree);

        byte[] nvRead = tpm[session].NvRead(nvHandle, nvHandle, size, 0);
        tpm.FlushContext(session);

        return nvRead;

    }
    catch (System.Exception ex)
    {
        Console.WriteLine($"StoreDataToNV Error Message:{ex.Message},InnerException:{ex.InnerException},StackTrace:{ex.StackTrace}");
    }

    return default;
}




byte[] Decrypt(Tpm2 tpm, byte[] useAuth, byte[] encryptedData, TpmHandle keyHandle)
{
    System.Console.WriteLine("set auth...");
    //身份认证
    keyHandle.SetAuth(useAuth);

    System.Console.WriteLine("decrypt data...");
    byte[] decryptedData = tpm.RsaDecrypt(keyHandle, encryptedData, new NullAsymScheme(), null);

    System.Console.WriteLine("decrypt data success!");
    return decryptedData;
}


TpmHandle CreatePrimaryRsaKey(Tpm2 tpm, TpmAlgId tpmAlgId, byte[] useAuth = null)
{
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

    System.Console.WriteLine("create sensitive data...");
    SensitiveCreate sensCreate = new SensitiveCreate(useAuth, null);

    System.Console.WriteLine("create primary key...");
    TpmHandle keyHandle = tpm.CreatePrimary(TpmRh.Null,
                                            sensCreate,
                                            tpmPublic,
                                            null,
                                            null,
                                            out TpmPublic keyPublic,
                                            out CreationData creationData,
                                            out byte[] creationHash,
                                            out TkCreation creationTicket);
    return keyHandle;
}
