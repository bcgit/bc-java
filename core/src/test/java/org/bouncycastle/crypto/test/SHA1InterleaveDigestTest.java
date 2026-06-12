package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.digests.SHA1InterleaveDigest;
import org.bouncycastle.util.encoders.Hex;

/**
 * Test for the SHA_Interleave function from RFC 2945, section 3.1.
 */
public class SHA1InterleaveDigestTest
    extends DigestTest
{
    private static String[] messages =
    {
        "",
        "a",                  // odd length - leading byte removed, same as empty
        "abc",                // odd length - 'a' removed
        "abcdefghij",
        "abcdefghijklmnopqrstuvwxyz"
    };

    private static String[] digests =
    {
        "dada3939a3a3eeee5e5e6b6b4b4b0d0d32325555bfbfefef9595606018189090afafd8d807070909",
        "dada3939a3a3eeee5e5e6b6b4b4b0d0d32325555bfbfefef9595606018189090afafd8d807070909",
        "e984d7a51f165e84e71bc9a72d7a6d5bc946e9482fdefd2cadd017dfb8cbbd3049ea41468fdb98b4",
        "93d5533ac2a3039c865a701a602fc73f7cba8af5b83fde1f4738fd4bf35cde2ee4a97c050153b71a",
        "3bf0f280a7951b1d5ba1d570d124b44409968619682e23939eecaaab92b8ed51851865d1d9e0c6e6"
    };

    SHA1InterleaveDigestTest()
    {
        super(new SHA1InterleaveDigest(), messages, digests);
    }

    public void performTest()
    {
        super.performTest();

        // leading zero bytes are removed before processing
        binaryVectorTest("leading zeros",
            "00000123456789abcdef0123456789abcdef",
            "d74ad180ff4b5cd62f3f8d6d3dfbc2492f5601dcbac10d8ccc8efe9cd7852874d8a306fe661f58c2");
        binaryVectorTest("no leading zeros",
            "0123456789abcdef0123456789abcdef",
            "d74ad180ff4b5cd62f3f8d6d3dfbc2492f5601dcbac10d8ccc8efe9cd7852874d8a306fe661f58c2");

        // leading zero removal followed by odd-length first byte removal
        binaryVectorTest("zero strip then odd",
            "000102030405060708090a0b0c0d0e0f",
            shaInterleaveOf("02030405060708090a0b0c0d0e0f"));

        checkDigestReset(this, new SHA1InterleaveDigest());

        try
        {
            new SHA1InterleaveDigest().doFinal(new byte[39], 0);
            fail("no exception for short output buffer");
        }
        catch (OutputLengthException e)
        {
            isTrue("output buffer too short".equals(e.getMessage()));
        }
    }

    private String shaInterleaveOf(String hexInput)
    {
        SHA1InterleaveDigest digest = new SHA1InterleaveDigest();
        byte[] input = Hex.decode(hexInput);
        byte[] result = new byte[digest.getDigestSize()];

        digest.update(input, 0, input.length);
        digest.doFinal(result, 0);

        return Hex.toHexString(result);
    }

    private void binaryVectorTest(String name, String hexInput, String hexExpected)
    {
        if (!hexExpected.equals(shaInterleaveOf(hexInput)))
        {
            fail("vector test " + name + " failed");
        }
    }

    protected Digest cloneDigest(Digest digest)
    {
        return new SHA1InterleaveDigest((SHA1InterleaveDigest)digest);
    }

    public static void main(
        String[]    args)
    {
        runTest(new SHA1InterleaveDigestTest());
    }
}
