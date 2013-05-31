package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.macs.SipHash;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.Pack;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/*
 * SipHash test values from "SipHash: a fast short-input PRF", by Jean-Philippe
 * Aumasson and Daniel J. Bernstein (https://131002.net/siphash/siphash.pdf), Appendix A.
 */
public class SipHashTest
    extends SimpleTest
{

    public String getName()
    {
        return "SipHash";
    }

    public void performTest()
        throws Exception
    {

        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] input = Hex.decode("000102030405060708090a0b0c0d0e");

        long expected = 0xa129ca6149be45e5L;

        SipHash mac = new SipHash();
        mac.init(new KeyParameter(key));
        mac.update(input, 0, input.length);

        long result = mac.doFinal();
        if (expected != result)
        {
            fail("Result does not match expected value for doFinal()");
        }

        byte[] expectedBytes = new byte[8];
        Pack.longToLittleEndian(expected, expectedBytes, 0);

        mac.update(input, 0, input.length);

        byte[] output = new byte[mac.getMacSize()];
        int len = mac.doFinal(output, 0);
        if (len != output.length)
        {
            fail("Result length does not equal getMacSize() for doFinal(byte[],int)");
        }
        if (!areEqual(expectedBytes, output))
        {
            fail("Result does not match expected value for doFinal(byte[],int)");
        }
    }

    public static void main(String[] args)
    {
        runTest(new SipHashTest());
    }
}
