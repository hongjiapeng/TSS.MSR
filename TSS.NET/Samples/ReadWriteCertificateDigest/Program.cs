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

    //var cstr = "Hello World!"; // Define a string constant, which is the content to be encrypted

    //byte[] data = Encoding.ASCII.GetBytes(cstr);

    // Define tiered storage password
    //string ownerpwd = "E(H+mbQW";

    //byte[] ownerAuth = Encoding.ASCII.GetBytes(ownerpwd);
    //tpm.OwnerAuth.AuthVal = ownerAuth;

    // Password authorization, that is, identity authentication, here is the password, other methods can also be used, such as HMAC\Policy, etc.
    string nvIndexPassword = "password2"; // Used for identity authentication, unrelated to encryption and decryption

    byte[] authValue = Encoding.ASCII.GetBytes(nvIndexPassword);

    string certDigestPath = @"C:\Work\Xiaowei\NewXiaowei\XiaoweiPackage\bin\x64\Release\XiaoweiPackage_3.0.39.0_x64.cer";

    ushort size = StoreCertDigestToNV(tpm, tpmAlgId, authValue, certDigestPath);

    ReadCertDigest(tpm, tpmAlgId, size);

    Console.ReadLine();
}


void ReadCertDigest(Tpm2 tpm, TpmAlgId hashAlg, ushort dataSize)
{

    TpmHandle nvHandle = TpmHandle.NV(5002);

    //define policy 

    PolicyTree policyTree = new PolicyTree(hashAlg);

    policyTree.Create(new PolicyAce[]
    {
        new TpmPolicyCommand(TpmCc.NvRead),
    });

    tpm.NvReadPublic(nvHandle, out byte[] name);

    nvHandle.SetName(name);

    //create session

    AuthSession policySession = tpm.StartAuthSessionEx(TpmSe.Policy, hashAlg);

    policySession.RunPolicy(tpm, policyTree);

    //read cert digest

    byte[] certDigest = tpm[policySession].NvRead(nvHandle, nvHandle, dataSize, 0);

    //output cert digest

    string dataHexString = BitConverter.ToString(certDigest).Replace("-", "").ToLower();

    Console.WriteLine($"certDigest: {dataHexString}");

    tpm.FlushContext(policySession);

    //自行实现对比证书摘要的过程
}

ushort StoreCertDigestToNV(Tpm2 tpm, TpmAlgId hashAlg, byte[] authValue,string certDigestPath)
{
    try
    {
        if (!File.Exists(certDigestPath))
        {
            throw new Exception("certDigestPath not exist");
        }

        var slotValue = 5002;

        // Define the NV storage area with AuthWrite attribute and a policy
        TpmHandle nvHandle = TpmHandle.NV(slotValue);

        // Clean up any slot that was left over from an earlier run
        // Delete the nvHandle first, otherwise it will report an error when creating
        tpm._AllowErrors().NvUndefineSpace(TpmRh.Owner, nvHandle);

        Console.WriteLine($"Start read cert digest, path: {certDigestPath}");

        byte[] data = File.ReadAllBytes(certDigestPath);

        //calculate policy digest
        List<byte> buffer = new List<byte>();

        TpmHandle hashHandle = tpm.HashSequenceStart(null, hashAlg);

        int offset = 0;

        foreach (var b in data)
        {
            buffer.Add(b);
            if (++offset >= 1024)
            {
                tpm.SequenceUpdate(hashHandle, buffer.ToArray());
                buffer.Clear();
                offset = 0;
            }
        }

        byte[] digest = tpm.SequenceComplete(hashHandle, buffer.ToArray(), TpmHandle.RhNull, out TkHashcheck ticket);

        ushort datalength = (ushort)digest.Length;

        Console.WriteLine($"digest length:{datalength}");

        //define policy

        PolicyTree policyTree = new PolicyTree(hashAlg);

        policyTree.Create(new PolicyAce[]
        {
            new TpmPolicyCommand(TpmCc.NvRead),
        });

        //calculate policy digest
        TpmHash policyDigest = policyTree.GetPolicyDigest();

        //define NV Index template
        var publicInfo = new NvPublic(nvHandle,
                hashAlg,
                NvAttr.Policyread | NvAttr.Authwrite,
                policyDigest, datalength);

        //Create a non -volatile storage area, which is equivalent to a disk, and the data written to it will not be lost
        tpm.NvDefineSpace(TpmRh.Owner, authValue, publicInfo);

        nvHandle.SetAuth(authValue);

        tpm.NvWrite(nvHandle, nvHandle, digest, 0);

        Console.WriteLine("StoreCertDigestToNV successfully!");

        return datalength;
    }
    catch (System.Exception ex)
    {
        Console.WriteLine($"StoreDataToNV Error Message:{ex.Message},InnerException:{ex.InnerException},StackTrace:{ex.StackTrace}");
    }

    return default;
}
