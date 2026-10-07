package org.bouncycastle.oer.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.oer.BitBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * BitBuilder sized its output as (pos + pos % 8) / 8, which is the octet count only when the bit
 * count is a multiple of 4: three bits wrote nothing and nine wrote one octet, dropping the partial
 * final octet. pad() had the same arithmetic. The one caller writes whole octets, so it never showed.
 */
public class BitBuilderTest
    extends TestCase
{
    public void testPartialFinalOctetIsWritten()
        throws IOException
    {
        for (int bitCount = 0; bitCount <= 40; ++bitCount)
        {
            BitBuilder bb = new BitBuilder();
            for (int i = 0; i < bitCount; ++i)
            {
                bb.writeBit(1);
            }
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            int written = bb.write(bOut);
            assertEquals(bitCount + " bits", (bitCount + 7) / 8, written);
            assertEquals(bitCount + " bits", written, bOut.size());

            byte[] expected = new byte[(bitCount + 7) / 8];
            for (int i = 0; i < bitCount; ++i)
            {
                expected[i / 8] |= (byte)(0x80 >>> (i % 8));
            }
            assertTrue(bitCount + " bits", Arrays.areEqual(expected, bOut.toByteArray()));
        }

        BitBuilder bb = new BitBuilder();
        bb.writeBit(1).writeBit(0).writeBit(1);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        bb.write(bOut);
        assertEquals("A0", Hex.toHexString(bOut.toByteArray()).toUpperCase());
    }

    /** Past the initial buffer: the builder grows and nothing already written is lost. */
    public void testGrowth()
        throws IOException
    {
        int bitCount = 16 * 8 * 3 + 5;
        BitBuilder bb = new BitBuilder();
        for (int i = 0; i < bitCount; ++i)
        {
            bb.writeBit(i % 3 == 0 ? 1 : 0);
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        bb.writeAndClear(bOut);
        byte[] out = bOut.toByteArray();
        assertEquals((bitCount + 7) / 8, out.length);
        for (int i = 0; i < bitCount; ++i)
        {
            assertEquals("bit " + i, i % 3 == 0, (out[i / 8] & (0x80 >>> (i % 8))) != 0);
        }
        for (int i = bitCount; i < out.length * 8; ++i)
        {
            assertEquals("pad bit " + i, 0, out[i / 8] & (0x80 >>> (i % 8)));
        }
    }

    public void testPadAdvancesToOctetBoundary()
        throws IOException
    {
        for (int bitCount = 0; bitCount <= 24; ++bitCount)
        {
            BitBuilder bb = new BitBuilder();
            for (int i = 0; i < bitCount; ++i)
            {
                bb.writeBit(1);
            }
            bb.pad();
            bb.writeBit(1);
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            bb.write(bOut);
            // the bit after the pad lands at the top of the next octet
            int expectedOctets = (bitCount + 7) / 8 + 1;
            assertEquals(bitCount + " bits then pad", expectedOctets, bOut.size());
            assertEquals(bitCount + " bits then pad", (byte)0x80, bOut.toByteArray()[expectedOctets - 1]);
        }
    }

    public void testWriteBitsTopBit()
        throws IOException
    {
        BitBuilder bb = new BitBuilder();
        bb.writeBits(Long.MIN_VALUE, 64);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        bb.write(bOut);
        assertEquals("8000000000000000", Hex.toHexString(bOut.toByteArray()).toUpperCase());
    }
}
