using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Tpm2Lib;

namespace TPM2_Ops
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (!(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux)))
            {
                throw new PlatformNotSupportedException();
            }
            string challenge = "";
            string userKeyauth = "";
            string op = "";
            if (args.Length == 1 && args[0] == "CREATE") 
            {
                op = args[0];
            } else if (args.Length == 3 && args[0] == "SIGN" && args[1] != null && args[1].Trim().Length > 0 && args[2] != null && args[2].Trim().Length > 0) 
            {
                op = args[0];
                challenge = args[1];
                userKeyauth = args[2];
            }

            if (op.Length != 0) 
            {
                Tpm2Device tpmDevice = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? new TbsDevice() : new LinuxTpmDevice();
                tpmDevice.Connect();
                var tpm = new Tpm2(tpmDevice);

                var ownerAuth = new AuthValue();
                var keyTemplate = new TpmPublic(
                    TpmAlgId.Sha256,
                    ObjectAttr.UserWithAuth | ObjectAttr.Sign |     // Signing key
                    ObjectAttr.FixedParent | ObjectAttr.FixedTPM |  // Non-migratable 
                    ObjectAttr.SensitiveDataOrigin,
                    null,                                           // No policy
                    new RsaParms(
                        new SymDefObject(),
                        new SchemeRsassa(TpmAlgId.Sha256), 2048, 0
                    ),
                    new Tpm2bPublicKeyRsa()
                );

                var keyAuth = op == "SIGN" ? Convert.FromHexString(userKeyauth) : RandomNumberGenerator.GetBytes(32);

                TpmPublic keyPublic;
                TpmHandle keyHandle = tpm[ownerAuth].CreatePrimary(
                    TpmRh.Owner,                            // In the owner-hierarchy
                    new SensitiveCreate(keyAuth, null),     // With this auth-value
                    keyTemplate,                            // Describes key
                    null,                                   // Extra data for creation ticket
                    new PcrSelection[0],                    // Non-PCR-bound
                    out keyPublic,                          // PubKey and attributes
                    out CreationData creationData, out byte[] creationHash, out TkCreation creationTicket
                );

                if (op == "CREATE")
                {
                    var buf = keyPublic.unique as Tpm2bPublicKeyRsa;
                    if (buf == null)
                    {
                        Console.WriteLine("FAIL");
                    } else
                    {
                        Console.WriteLine(Convert.ToHexString(buf.buffer) + "#" + Convert.ToHexString(keyAuth));
                    }
                } else if (op == "SIGN")
                {
                    byte[] message = Encoding.Unicode.GetBytes(challenge);
                    TpmHash digestToSign = TpmHash.FromData(TpmAlgId.Sha256, message);

                    var signature = tpm[keyAuth].Sign(
                        keyHandle,            // Handle of signing key
                        digestToSign,         // Data to sign
                        null,                 // Use key's scheme
                        TpmHashCheck.Null()
                    ) as SignatureRsassa;
                    if (signature == null)
                    {
                        Console.WriteLine("FAIL");
                    }

                    try
                    {
                        TpmHandle pubHandle = tpm.LoadExternal(null, keyPublic, TpmRh.Owner);
                        tpm.VerifySignature(pubHandle, digestToSign, signature);
                        tpm.FlushContext(pubHandle);
                        Console.WriteLine(Convert.ToHexString(signature!.sig));
                    } catch
                    {
                        Console.WriteLine("FAIL");
                    }
                }

                tpm.FlushContext(keyHandle);
                tpm.Dispose();
            }
        }
    }
}
