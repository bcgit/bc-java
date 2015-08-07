package org.bouncycastle.jce.provider.test;

import java.security.MessageDigest;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class KeccakTest
    extends SimpleTest
{
    final static String provider = "BC";

    static private byte[] nullMsg = new byte[0];

    static private String[][] nullVectors =
    {
        { "KECCAK-224", "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd" },
        { "KECCAK-256", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" },
        { "KECCAK-384", "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff" },
        { "KECCAK-512", "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e" },
    };

    static private byte[] shortMsg = Hex.decode("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67");

    static private String[][] shortVectors =
    {
        { "KECCAK-224", "310aee6b30c47350576ac2873fa89fd190cdc488442f3ef654cf23fe" },
        { "KECCAK-256", "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15" },
        { "KECCAK-384", "283990fa9d5fb731d786c5bbee94ea4db4910f18c62c03d173fc0a5e494422e8a0b3da7574dae7fa0baf005e504063b3" },
        { "KECCAK-512", "d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609" },
    };

    public String getName()
    {
        return "KECCAK";
    }

    void test(String algorithm, byte[] message, String expected)
        throws Exception
    {
        MessageDigest digest = MessageDigest.getInstance(algorithm, provider);

        byte[] result = digest.digest(message);
        byte[] result2 = digest.digest(message);

        // test zero results valid
        if (!MessageDigest.isEqual(result, Hex.decode(expected)))
        {
            fail("null result not equal for " + algorithm);
        }
        
        // test one digest the same message with the same instance
        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 1 not equal");
        }

        if (!MessageDigest.isEqual(result, Hex.decode(expected)))
        {
            fail("Result object 1 not equal");
        }

        // test two, single byte updates
        for (int i = 0; i < message.length; i++)
        {
            digest.update(message[i]);
        }
        result2 = digest.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 2 not equal");
        }

        // test three, two half updates
        digest.update(message, 0, message.length/2);
        digest.update(message, message.length/2, message.length-message.length/2);
        result2 = digest.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 3 not equal");
        }

        // test four, clone test
        digest.update(message, 0, message.length/2);
        MessageDigest d = (MessageDigest)digest.clone();
        digest.update(message, message.length/2, message.length-message.length/2);
        result2 = digest.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 4(a) not equal");
        }

        d.update(message, message.length/2, message.length-message.length/2);
        result2 = d.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 4(b) not equal");
        }

        // test five, check reset() method
        digest.update(message, 0, message.length/2);
        digest.reset();
        digest.update(message, 0, message.length/2);
        digest.update(message, message.length/2, message.length-message.length/2);
        result2 = digest.digest();

        if (!MessageDigest.isEqual(result, result2))
        {
            fail("Result object 5 not equal");
        }
        
    }

    public void performTest()
        throws Exception
    {
        for (int i = 0; i != nullVectors.length; i++)
        {
            test(nullVectors[i][0], nullMsg, nullVectors[i][1]);
            test(shortVectors[i][0], shortMsg, shortVectors[i][1]);
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new KeccakTest());
    }
}
