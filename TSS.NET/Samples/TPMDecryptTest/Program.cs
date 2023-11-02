// See https://aka.ms/new-console-template for more information
using System.Text;
using Tpm2Lib;
{
    TpmAlgId tpmAlgId = TpmAlgId.Sha1;
    System.Console.WriteLine("create tpm device...");
    Tpm2Device tpmDevice = new TbsDevice();

    System.Console.WriteLine("connect tpm device...");
    tpmDevice.Connect();

    System.Console.WriteLine("create tpm object...");
    var tpm = new Tpm2(tpmDevice);

    var cstr = "Hello World!";

    byte[] data = Encoding.ASCII.GetBytes(cstr);

    string cpwd = "password";

    byte[] useAuth = Encoding.ASCII.GetBytes(cpwd);

    //加密与解密方法必须使用同一个Handle，才能完成加解密，
    //否则如果是不同的Handle，那么指向的是不同的内存区域，也就是不同的密钥

    TpmHandle keyHandle = CreatePrimaryRsaKey(tpm,tpmAlgId, useAuth);

    string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

    string filePath = Path.Combine(desktopPath, "encrypt_data.dat");

    Console.WriteLine($"encrypt data file save path:{filePath}");

    byte[] encrypedData = File.ReadAllBytes(filePath);

    Console.WriteLine($"encrypt data read success!");

    //TpmPublic keyPublic = tpm.ReadPublic(keyHandle,  out byte[] name, out byte[] keyName);

    //TpmHandle loadedKeyHandle = tpm.Load(TpmRh.Owner, keyPublic, keyName);
    try
    {

        //最后,我们使用RSA密钥的私钥对数据进行解密
        byte[] decryptedData = Decrypt(tpm, useAuth, encrypedData, keyHandle);

        string encryptedString = BitConverter.ToString(encrypedData);
        string decryptedString = BitConverter.ToString(decryptedData);

        string dataHexString = BitConverter.ToString(data);

        //然后将名文数据、加密数据以及解密后的数据进行输出
        Console.WriteLine($"raw data:{dataHexString}");

        Console.WriteLine($"encrypt data:{encryptedString}");

        Console.WriteLine($"decrypt data:{decryptedString}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Decrypt Error Message:{ex.Message},InnerException:{ex.InnerException},StackTrace:{ex.StackTrace}");       
    }
    finally
    {
        Console.WriteLine("press any key to exit...");
    }

    Console.ReadLine();
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
