package org.bouncycastle.crypto.test;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2PSSSigner;
import org.bouncycastle.crypto.signers.ISO9796d2Signer;
import org.bouncycastle.crypto.signers.X931Signer;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class IsoTrailerTest
    extends SimpleTest
{
    private static final byte[] x931SigOld = Hex.decode("33156b44e30640d14940d5f4534de6a91c945fe8355b01f66a896c41c78482ba02457d079327bd7015a875c353c6a0db356d6c568edb07dbbdb0500705e3f8aff9269f8535c1ed27edb09a1c246a366c4f638fd224389bcaebeb2dedc400990b91cddfda4ee0abc67ae1e39b139183dd6193aee9aa3616285ba928af20f89d5c");
    private static final byte[] x931SigCorrect =  Hex.decode("3ff8d8c371503a153bb99edb1064984680ef7f70f73d08d28205b8e1ae90d7a00d78d6f16994b872bf613aafb41dd7b60fc9e964d280bde07637ec278b9491ddeeecae53e2b55302801577b20cda4ef2d4a42868de579fa5a50f2f2feb50688d893d9210469bb47134475515a7745744ba99e23d4490400e7a734e00ef2c5476");

    private static final byte[] iso9796d2Old = Hex.decode("07f7c6a8726aeed821ce7af09b5eb260ade66913c5548438f5f7a613f5e96e1638c36d22d968c24abfa7b5879cbdf55985e7928553fe33a9c7e53b85daab87cc661e33cc1290832c3cfda59256f9501657efead29ee45cc06df1e1c0f3e06110e46377c6ed5ec78327d1c7787af79287e50c810ed17a2b43c56d27ec695b4dbf");
    private static final byte[] iso9796d2Correct = Hex.decode("530c8949deb24d138b175db5be846481f8b22598fcc44476caf87fe4f5f8c9b71f9456791bf47aaafa20650fedc000251f4eee1bcaed57bd5d1b1e64b5d0e460df88e4a5266eb3969577d29a80d7d0038044247ae6fe7705f9d20d0ef42f525445de0560c9c3972c6443be779c762cfb08e403fc2f06bc8e2d7b8f3bf022160a");

    private static final byte[] iso9796d2PSSOld = Hex.decode("274dbd6e3d93672ee5121022843e37f66b1ff12bb7f04cff059d76932ce9116e8b12efcd19d98a78f8c9d3f262fd3ce7c3bca0edc223f3af54e1401b37f807ef5b6d71591a22a40a34ce8abc10164138835bb63ac8eeb0223d1e1d8c5d18da2acac7f7061023597aa338c4af96bebe6c7935e0b5603cb87977b9e345f697ff98");
    private static final byte[] iso9796d2PSSCorrect = Hex.decode("3a5c1248652cd6fd4419064b894379ad48c8596a3a5a0bdf98b6d6a9d25f5df164591beddff9e2ae88100dd165053f0edd2e4154834ea7b7c1f56312c4fe23a5407cf73a2c4540c8c19e91187f709529ebb779db2f8fa39f6bef923c392abecf9e7596927a71f62990dafd8bf00d298863d07680e75b1bb9bb655ba25ff48d1e");
    
    public String getName()
    {
        return "IsoTrailerTest";
    }

    private void x931Sha512_256Test()
    {
        BigInteger rsaPubMod = new BigInteger(Base64.decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
        BigInteger rsaPubExp = new BigInteger(Base64.decode("EQ=="));

        RSAKeyParameters rsaPublic = new RSAKeyParameters(false, rsaPubMod, rsaPubExp);

        byte[] msg = new byte[] { 1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23 };

        X931Signer signer = new X931Signer(new RSAEngine(), new SHA512tDigest(256));
        signer.init(false, rsaPublic);
        signer.update(msg, 0, msg.length);
        if (!signer.verifySignature(x931SigCorrect))
        {
            fail("X9.31 Signer failed.");
        }

        signer.init(false, rsaPublic);
        signer.update(msg, 0, msg.length);
        if (!signer.verifySignature(x931SigOld))
        {
            fail("X9.31 old Signer failed.");
        }
    }

    private void iso9796_2Sha512_256Test()
    {
        BigInteger rsaPubMod = new BigInteger(Base64.decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
        BigInteger rsaPubExp = new BigInteger(Base64.decode("EQ=="));

        RSAKeyParameters rsaPublic = new RSAKeyParameters(false, rsaPubMod, rsaPubExp);

        byte[] msg = new byte[] { 1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23 };

        ISO9796d2Signer signer = new ISO9796d2Signer(new RSAEngine(), new SHA512tDigest(256));

        signer.init(false, rsaPublic);
        signer.update(msg, 0, msg.length);
        if (!signer.verifySignature(iso9796d2Correct))
        {
            fail("ISO9796-2 Signer failed.");
        }

        signer.init(false, rsaPublic);
        signer.update(msg, 0, msg.length);
        if (!signer.verifySignature(iso9796d2Old))
        {
            fail("ISO9796-2 old Signer failed.");
        }
    }

    private void iso9796_2PSSSha512_256Test()
    {
        BigInteger rsaPubMod = new BigInteger(Base64.decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
        BigInteger rsaPubExp = new BigInteger(Base64.decode("EQ=="));

        RSAKeyParameters rsaPublic = new RSAKeyParameters(false, rsaPubMod, rsaPubExp);

        byte[] msg = new byte[] { 1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23 };

        ISO9796d2PSSSigner signer = new ISO9796d2PSSSigner(new RSAEngine(), new SHA512tDigest(256), 32);

        signer.init(false, rsaPublic);
        signer.update(msg, 0, msg.length);
        if (!signer.verifySignature(iso9796d2PSSCorrect))
        {
            fail("ISO9796-2PSS Signer failed.");
        }

        signer.init(false, rsaPublic);
        signer.update(msg, 0, msg.length);
        if (!signer.verifySignature(iso9796d2PSSOld))
        {
            fail("ISO9796-2PSS old Signer failed.");
        }
    }
    
    public void performTest()
        throws Exception
    {
        x931Sha512_256Test();
        iso9796_2Sha512_256Test();
        iso9796_2PSSSha512_256Test();
    }

    public static void main(
        String[]    args)
    {
        runTest(new IsoTrailerTest());
    }
}
