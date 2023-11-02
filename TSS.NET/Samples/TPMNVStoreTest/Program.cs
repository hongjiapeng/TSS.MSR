// See https://aka.ms/new-console-template for more information
using System;
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

    byte[] data = new byte[] { 0, 1, 2, 3, 4, 5, 9, 7 };

    // 定义分层存储密码
    //string ownerpwd = "E(H+mbQW";

    //byte[] ownerAuth = Encoding.ASCII.GetBytes(ownerpwd);
    //tpm.OwnerAuth.AuthVal = ownerAuth;

    // Password authorization, that is, identity authentication, here is the password, other methods can also be used, such as HMAC\Policy, etc.
    string nvIndexPassword = "password2"; // Used for identity authentication, unrelated to encryption and decryption

    byte[] authValue = Encoding.ASCII.GetBytes(nvIndexPassword);

    string dataHexString = BitConverter.ToString(data);

    // Then output the plaintext data, encrypted data and decrypted data
    Console.WriteLine($"Raw data: {dataHexString}");

    ushort nVSize = (ushort)data.Length;

  //StoreDataToNV(tpm, tpmAlgId, authValue, data, nVSize);

    StoreDataToNVWithPolicy(tpm, tpmAlgId, authValue, data, nVSize);

    //StoreDataToNVWithPolicy2(tpm, tpmAlgId, authValue, data, nVSize);

    Console.ReadLine();
}

void StoreDataToNVWithPolicy(Tpm2 tpm, TpmAlgId hashAlg, byte[] authValue, byte[] data, ushort nVSize = 32)
{
    try
    {
        var slotValue = 5001;

        // Define the NV storage area with AuthWrite attribute and a policy
        TpmHandle nvHandle = TpmHandle.NV(slotValue);

        // Clean up any slot that was left over from an earlier run
        // Delete the nvHandle first, otherwise it will report an error when creating
        tpm._AllowErrors().NvUndefineSpace(TpmRh.Owner, nvHandle);

        //define policy
        PolicyTree policyTree = new PolicyTree(hashAlg);
        policyTree.Create(new PolicyAce[]
        {
            new TpmPolicyAuthValue(),
        });

        //calculate policy digest
        TpmHash policyDigest = policyTree.GetPolicyDigest();

        //define NV Index
        var publicInfo = new NvPublic(nvHandle,
                hashAlg,
                NvAttr.Policyread | NvAttr.Policywrite,
                policyDigest, 32);

        //Create a non -volatile storage area, which is equivalent to a disk, and the data written to it will not be lost
        tpm.NvDefineSpace(TpmRh.Owner, authValue, publicInfo);

        nvHandle.SetAuth(authValue);

        tpm.NvReadPublic(nvHandle, out byte[] name);

        nvHandle.SetName(name);

        AuthSession session = tpm.StartAuthSessionEx(TpmSe.Policy, hashAlg);

        session.RunPolicy(tpm, policyTree);

        tpm[session].NvWrite(nvHandle, nvHandle, data, 0);

        Console.WriteLine("Store data to nv successfully!");

        tpm.FlushContext(session);

        Console.WriteLine("flush context sucessfully");
    }
    catch (System.Exception ex)
    {
        Console.WriteLine($"StoreDataToNV Error Message:{ex.Message},InnerException:{ex.InnerException},StackTrace:{ex.StackTrace}");
    }
}


//创建读写分离授权模型
void StoreDataToNVWithPolicy2(Tpm2 tpm, TpmAlgId hashAlg, byte[] authValue, byte[] data, ushort nVSize = 32)
{
    try
    {

        var slotValue = 5002;

        // Define the NV storage area with AuthWrite attribute and a policy
        TpmHandle nvHandle = TpmHandle.NV(slotValue);

        // Clean up any slot that was left over from an earlier run
        // Delete the nvHandle first, otherwise it will report an error when creating
        tpm._AllowErrors().NvUndefineSpace(TpmRh.Owner, nvHandle);

        //define policy
        PolicyTree policyTree = new PolicyTree(hashAlg);
        policyTree.Create(new PolicyAce[]
        {
            new TpmPolicyCommand(TpmCc.NvRead),
        });

        //calculate policy digest
        TpmHash policyDigest = policyTree.GetPolicyDigest();

        //define NV Index
        //var publicInfo = new NvPublic(nvHandle,
        //        hashAlg,
        //        NvAttr.Policyread | NvAttr.Policywrite,
        //        policyDigest, 32);

        var publicInfo = new NvPublic(nvHandle,
                hashAlg,
                NvAttr.Policyread | NvAttr.Authwrite,
                policyDigest, 32);

        //Create a non -volatile storage area, which is equivalent to a disk, and the data written to it will not be lost
        tpm.NvDefineSpace(TpmRh.Owner, authValue, publicInfo);


        //tpm.NvDefineSpace(TpmRh.Owner, authValue,
        //                  new NvPublic(nvHandle, TpmAlgId.Sha1,
        //                               NvAttr.Authread | NvAttr.Authwrite,
        //                               null, nVSize));

        nvHandle.SetAuth(authValue);

        tpm.NvReadPublic(nvHandle, out byte[] name);

        nvHandle.SetName(name);

        AuthSession session = tpm.StartAuthSessionEx(TpmSe.Policy, hashAlg);

        session.RunPolicy(tpm, policyTree);

        tpm[session].NvWrite(nvHandle, nvHandle, data, 0);

        Console.WriteLine("Store data to nv successfully!");

        tpm.FlushContext(session);

        Console.WriteLine("flush context sucessfully");
    }
    catch (System.Exception ex)
    {
        Console.WriteLine($"StoreDataToNV Error Message:{ex.Message},InnerException:{ex.InnerException},StackTrace:{ex.StackTrace}");
    }
}


//void StoreDataToNV(Tpm2 tpm, TpmAlgId hashAlg, byte[] authValue, byte[] data, ushort nVSize = 32)
//{
//    try
//    {
//        var slotValue = 5001;

//        // Define the NV storage area with AuthWrite attribute and a policy
//        TpmHandle nvHandle = TpmHandle.NV(slotValue);

//        // Delete the nvHandle first, otherwise it will report an error when creating
//        tpm._AllowErrors().NvUndefineSpace(TpmRh.Owner, nvHandle);

//        //var publicInfo = new NvPublic(nvHandle, hashAlg, NvAttr.Authread | NvAttr.Authwrite, null, 32);

//        //Create a non -volatile storage area, which is equivalent to a disk, and the data written to it will not be lost

//        //tpm.NvDefineSpace(TpmRh.Owner, authValue, publicInfo);


//        tpm.NvDefineSpace(TpmRh.Owner, authValue,
//                          new NvPublic(nvHandle, TpmAlgId.Sha1,
//                                       NvAttr.Authread | NvAttr.Authwrite,
//                                       null, nVSize));
//        //nvHandle.SetAuth(userAuth);

//        System.Console.WriteLine("write data to nv...");

//        // Create a non-volatile storage area, which is equivalent to a disk, and the data written to it will not be lost
//        tpm.NvWrite(nvHandle, nvHandle, data, 0);

//        Console.WriteLine("Store data to nv successfully!");
//    }
//    catch (System.Exception ex)
//    {
//        Console.WriteLine($"StoreDataToNV Error Message:{ex.Message},InnerException:{ex.InnerException},StackTrace:{ex.StackTrace}");
//    }
//}

//// We will create a pair of RSA keys, which include public and private keys
//// In asymmetric keys, the typical encryption scenario is to use the public key to encrypt data and the private key to decrypt data. Of course, this operation can also be reversed, and if reversed, it is called a digital signature
//// Because our example uses a public key to encrypt data, it is called asymmetric encryption
//byte[] Encrypt(TpmAlgId tpmAlgId, Tpm2 tpm, byte[] useAuth, byte[] data, ref TpmHandle keyHandle)
//{
//    // ObjectAttr is a multi-value parameter, which represents the attributes of the key. Here it means that the key is decryptable, requires user authentication, is sensitive data, and is original data
//    // SymDefObject is the parameter of the symmetric encryption algorithm. Here it means using the AES algorithm, the key length is 128 bits, and the mode is CFB
//    System.Console.WriteLine("create tpm public");
//    TpmPublic tpmPublic = new TpmPublic(
//         tpmAlgId,
//         ObjectAttr.Decrypt | ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin,
//         null,
//         new RsaParms(
//             new SymDefObject(),
//             new SchemeOaep(tpmAlgId),
//             2048,
//             65537),
//         new Tpm2bPublicKeyRsa());

//    System.Console.WriteLine("Creating sensitive data...");

//    SensitiveCreate sensCreate = new SensitiveCreate(useAuth, null);

//    System.Console.WriteLine("Creating key...");
//    keyHandle = tpm.CreatePrimary(TpmRh.Null,
//                                    sensCreate,
//                                    tpmPublic,
//                                    null,
//                                    null,
//                                    out TpmPublic keyPublic,
//                                    out CreationData creationData,
//                                    out byte[] creationHash,
//                                    out TkCreation creationTicket);

//    System.Console.WriteLine("Encrypting data...");
//    // Encrypt plaintext data with public key
//    byte[] encryptedData = keyPublic.EncryptOaep(data, null);

//    System.Console.WriteLine("Data encrypted successfully!");
//    return encryptedData;
//}