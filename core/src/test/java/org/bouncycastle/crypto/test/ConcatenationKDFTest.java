package org.bouncycastle.crypto.test;

import java.util.Random;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test vectors were copied from https://github.com/patrickfav/singlestep-kdf/wiki/NIST-SP-800-56C-Rev1:-Non-Official-Test-Vectors
 */
public class ConcatenationKDFTest
    extends SimpleTest
{
    public String getName()
    {
        return "ConcatenationKDF";
    }

    public void performTest()
    {
        implSHA1Test();
        implSHA256Test();
        implSHA512Test();
        implKDFPositiveLenTest();
    }

    private void implSHA1Test()
    {
        String sharedSecret = "ebe28edbae5a410b87a479243db3f690";
        String otherInfo = "e60dd8b28228ce5b9be74d3b";
        String expected = "b4a23963e07f485382cb358a493daec1759ac7043dbeac37152c6ddf105031f0f239f270b7f30616166f10e5d2b4cb11ba8bf4ba3f2276885abfbc3e811a568d480d9192";

        implKDFTest(new SHA1Digest(), sharedSecret, otherInfo, expected);
    }

    private void implSHA256Test()
    {
        String sharedSecret = "3f892bd8b84dae64a782a35f6eaa8f00";
        String otherInfo = "ec3f1cd873d28858a58cc39e";
        String expected = "a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf1c816f40ecd74aed8eda2b8a3c714fa0";

        implKDFTest(new SHA256Digest(), sharedSecret, otherInfo, expected);
    }

    private void implSHA512Test()
    {
        String sharedSecret = "e65b1905878b95f68b5535bd3b2b1013";
        String otherInfo = "830221b1730d9176f807d407";
        String expected = "b8c44bdf0b85a64b6a51c12a06710e373d829bb1fda5b4e1a20795c6199594f6fa65198a721257f7d58cb2f6f6db9bb5699f73863045909054b2389e06ec00fe318cabd9";

        implKDFTest(new SHA512Digest(), sharedSecret, otherInfo, expected);
    }

    private void implKDFTest(Digest digest, String sharedSecret, String otherInfo, String expected)
    {
        byte[] sharedSecretBytes = Hex.decodeStrict(sharedSecret);
        byte[] otherInfoBytes = Hex.decodeStrict(otherInfo);
        byte[] expectedBytes = Hex.decodeStrict(expected);
        byte[] output = new byte[15 + expectedBytes.length];

        Random random = new Random();
        ConcatenationKDFGenerator kdf = new ConcatenationKDFGenerator(digest);

        for (int count = 1; count <= expectedBytes.length; ++count)
        {
            Arrays.fill(output, (byte)0);
            int outputPos = random.nextInt(16);

            kdf.init(new KDFParameters(sharedSecretBytes, otherInfoBytes));
            kdf.generateBytes(output, outputPos, count);

            if (!Arrays.areEqual(expectedBytes, 0, count, output, outputPos, outputPos + count))
            {
                fail("ConcatenationKDF (" + digest.getAlgorithmName() + ") failed for count of " + count);
            }
        }
    }

    private void implKDFPositiveLenTest()
    {
        String sharedSecret = "e65b1905878b95f68b5535bd3b2b1013";
        String otherInfo = "830221b1730d9176f807d407";
        byte[] sharedSecretBytes = Hex.decodeStrict(sharedSecret);
        byte[] otherInfoBytes = Hex.decodeStrict(otherInfo);
        byte[] output = new byte[2048];

        ConcatenationKDFGenerator kdf = new ConcatenationKDFGenerator(new SHA512Digest());
        kdf.init(new KDFParameters(sharedSecretBytes, otherInfoBytes));
        try
        {
            kdf.generateBytes(output, 0, 0);
            fail("ConcatenationKDF must ignore the len parameter with value zero");
        }
        catch (IllegalArgumentException iae)
        {
            isEquals(
                "Expect valid ConcatenationKDF error message",
                "len must be > 0",
                iae.getMessage()
            );
        }

        try
        {
            kdf.generateBytes(output, 0, -1);
            fail("ConcatenationKDF must ignore the len parameter with negative value");
        }
        catch (IllegalArgumentException iae)
        {
            isEquals(
                "Expect valid ConcatenationKDF error message",
                "len must be > 0",
                iae.getMessage()
            );
        }
    }

    public static void main(String[] args)
    {
        runTest(new ConcatenationKDFTest());
    }
}
