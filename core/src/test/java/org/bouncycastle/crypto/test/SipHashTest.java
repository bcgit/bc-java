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
    private static final int UPDATE_BYTES = 0;
    private static final int UPDATE_FULL = 1;
    private static final int UPDATE_MIX = 2;

    public String getName()
    {
        return "SipHash";
    }

    public void performTest()
        throws Exception
    {
        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] input = Hex.decode("000102030405060708090a0b0c0d0e");

        runMAC(key, input, UPDATE_BYTES);
        runMAC(key, input, UPDATE_FULL);
        runMAC(key, input, UPDATE_MIX);
    }

    private void runMAC(byte[] key, byte[] input, int updateType)
        throws Exception
    {
        long expected = 0xa129ca6149be45e5L;

        SipHash mac = new SipHash();
        mac.init(new KeyParameter(key));

        updateMAC(mac, input, updateType);

        long result = mac.doFinal();
        if (expected != result)
        {
            fail("Result does not match expected value for doFinal()");
        }

        byte[] expectedBytes = new byte[8];
        Pack.longToLittleEndian(expected, expectedBytes, 0);

        updateMAC(mac, input, updateType);

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

    private void updateMAC(SipHash mac, byte[] input, int updateType)
    {
        switch (updateType)
        {
        case UPDATE_BYTES:
        {
            for (int i = 0; i < input.length; ++i)
            {
                mac.update(input[i]);
            }
            break;
        }
        case UPDATE_FULL:
        {
            mac.update(input, 0, input.length);
            break;
        }
        case UPDATE_MIX:
        {
            int step = Math.max(1, input.length / 3);
            int pos = 0;
            while (pos < input.length)
            {
                mac.update(input[pos++]);
                int len = Math.min(input.length - pos, step);
                mac.update(input, pos, len);
                pos += len;
            }
            break;
        }
        default:
            throw new IllegalStateException();
        }
    }

    public static void main(String[] args)
    {
        runTest(new SipHashTest());
    }
}
