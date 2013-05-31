package org.bouncycastle.crypto.test;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.Digest;

public class DigestRandomNumberTest
    extends SimpleTest
{
    private static final byte[] ZERO_SEED = { 0, 0, 0, 0, 0, 0, 0, 0 };

    private static final byte[] TEST_SEED = Hex.decode("81dcfafc885914057876");

    private static final byte[] expected0SHA1 = Hex.decode("95bca677b3d4ff793213c00892d2356ec729ee02");
    private static final byte[] noCycle0SHA1 = Hex.decode("d57ccd0eb12c3938d59226412bc1268037b6b846");
    private static final byte[] expected0SHA256 = Hex.decode("587e2dfd597d086e47ddcd343eac983a5c913bef8c6a1a560a5c1bc3a74b0991");
    private static final byte[] noCycle0SHA256 = Hex.decode("e5776c4483486ba7be081f4e1b9dafbab25c8fae290fd5474c1ceda2c16f9509");
    private static final byte[] expected100SHA1 = Hex.decode("b9d924092546e0876cafd4937d7364ebf9efa4be");
    private static final byte[] expected100SHA256 = Hex.decode("fbc4aa54b948b99de104c44563a552899d718bb75d1941cc62a2444b0506abaf");
    private static final byte[] expectedTestSHA1 = Hex.decode("e9ecef9f5306daf1ac51a89a211a64cb24415649");
    private static final byte[] expectedTestSHA256 = Hex.decode("bdab3ca831b472a2fa09bd1bade541ef16c96640a91fcec553679a136061de98");

    private static final byte[] sha1Xors = Hex.decode("7edcc1216934f3891b03ffa65821611a3e2b1f79");
    private static final byte[] sha256Xors = Hex.decode("5ec48189cc0aa71e79c707bc3c33ffd47bbba368a83d6cfebf3cd3969d7f3eed");

    public String getName()
    {
        return "DigestRandomNumber";
    }

    private void doExpectedTest(Digest digest, int seed, byte[] expected)
    {
        doExpectedTest(digest, seed, expected, null);
    }
    
    private void doExpectedTest(Digest digest, int seed, byte[] expected, byte[] noCycle)
    {
        DigestRandomGenerator rGen = new DigestRandomGenerator(digest);
        byte[] output = new byte[digest.getDigestSize()];

        rGen.addSeedMaterial(seed);

        for (int i = 0; i != 1024; i++)
        {
             rGen.nextBytes(output);
        }

        if (noCycle != null)
        {
            if (Arrays.areEqual(noCycle, output))
            {
                fail("seed not being cycled!");
            }
        }

        if (!Arrays.areEqual(expected, output))
        {
            fail("expected output doesn't match");
        }
    }

    private void doExpectedTest(Digest digest, byte[] seed, byte[] expected)
    {
        DigestRandomGenerator rGen = new DigestRandomGenerator(digest);
        byte[] output = new byte[digest.getDigestSize()];

        rGen.addSeedMaterial(seed);

        for (int i = 0; i != 1024; i++)
        {
             rGen.nextBytes(output);
        }

        if (!Arrays.areEqual(expected, output))
        {
            fail("expected output doesn't match");
        }
    }

    private void doCountTest(Digest digest, byte[] seed, byte[] expectedXors)
    {
        DigestRandomGenerator rGen = new DigestRandomGenerator(digest);
        byte[] output = new byte[digest.getDigestSize()];
        int[] averages = new int[digest.getDigestSize()];
        byte[] ands = new byte[digest.getDigestSize()];
        byte[] xors = new byte[digest.getDigestSize()];
        byte[] ors = new byte[digest.getDigestSize()];

        rGen.addSeedMaterial(seed);

        for (int i = 0; i != 1000000; i++)
        {
             rGen.nextBytes(output);
             for (int j = 0; j != output.length; j++)
             {
                 averages[j] += output[j] & 0xff;
                 ands[j] &= output[j];
                 xors[j] ^= output[j];
                 ors[j] |= output[j];
             }
        }
               
        for (int i = 0; i != output.length; i++)
        {
            if ((averages[i] / 1000000) != 127)
            {
                fail("average test failed for " + digest.getAlgorithmName());
            }
            if (ands[i] != 0)
            {
                fail("and test failed for " + digest.getAlgorithmName());
            }
            if ((ors[i] & 0xff) != 0xff)
            {
                fail("or test failed for " + digest.getAlgorithmName());
            }
            if (xors[i] != expectedXors[i])
            {
                fail("xor test failed for " + digest.getAlgorithmName());
            }
        }
    }

    public void performTest()
        throws Exception
    {
        doExpectedTest(new SHA1Digest(), 0, expected0SHA1, noCycle0SHA1);
        doExpectedTest(new SHA256Digest(), 0, expected0SHA256, noCycle0SHA256);

        doExpectedTest(new SHA1Digest(), 100, expected100SHA1);
        doExpectedTest(new SHA256Digest(), 100, expected100SHA256);

        doExpectedTest(new SHA1Digest(), ZERO_SEED, expected0SHA1);
        doExpectedTest(new SHA256Digest(), ZERO_SEED, expected0SHA256);

        doExpectedTest(new SHA1Digest(), TEST_SEED, expectedTestSHA1);
        doExpectedTest(new SHA256Digest(), TEST_SEED, expectedTestSHA256);

        doCountTest(new SHA1Digest(), TEST_SEED, sha1Xors);
        doCountTest(new SHA256Digest(), TEST_SEED, sha256Xors);
    }

    public static void main(
        String[]    args)
    {
        runTest(new DigestRandomNumberTest());
    }
}
