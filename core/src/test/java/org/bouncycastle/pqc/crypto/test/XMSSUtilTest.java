package org.bouncycastle.pqc.crypto.test;

import java.math.BigInteger;
import java.util.Arrays;

import junit.framework.TestCase;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
import org.bouncycastle.util.Pack;

/**
 * Test cases for XMSSUtil class.
 * 
 */
public class XMSSUtilTest
    extends TestCase
{

    public void testLog2()
    {
        assertEquals(3, XMSSUtil.log2(8));
        assertEquals(3, XMSSUtil.log2(10));
        assertEquals(26, XMSSUtil.log2(100010124));
    }

    public void testIntToBytesBigEndian()
    {
        byte[] b = XMSSUtil.toBytesBigEndian(1, 4);
        assertEquals(4, b.length);
        assertEquals((byte)0x00, b[0]);
        assertEquals((byte)0x00, b[1]);
        assertEquals((byte)0x00, b[2]);
        assertEquals((byte)0x01, b[3]);
        b = XMSSUtil.toBytesBigEndian(1, 6);
        assertEquals(6, b.length);
        assertEquals((byte)0x00, b[0]);
        assertEquals((byte)0x00, b[1]);
        assertEquals((byte)0x00, b[2]);
        assertEquals((byte)0x00, b[3]);
        assertEquals((byte)0x00, b[4]);
        assertEquals((byte)0x01, b[5]);
        b = XMSSUtil.toBytesBigEndian(1, 32);
        assertEquals(32, b.length);
        for (int i = 0; i < 31; i++)
        {
            assertEquals((byte)0x00, b[i]);
        }
        b = XMSSUtil.toBytesBigEndian(12345, 5);
        assertEquals(5, b.length);
        assertEquals((byte)0x00, b[0]);
        assertEquals((byte)0x00, b[1]);
        assertEquals((byte)0x00, b[2]);
        assertEquals((byte)0x30, b[3]);
        assertEquals((byte)0x39, b[4]);
    }

    public void testLongToBytesBigEndian()
    {
        byte[] b = XMSSUtil.toBytesBigEndian(1, 8);
        assertEquals(8, b.length);
        assertEquals((byte)0x00, b[0]);
        assertEquals((byte)0x00, b[1]);
        assertEquals((byte)0x00, b[2]);
        assertEquals((byte)0x00, b[3]);
        assertEquals((byte)0x00, b[4]);
        assertEquals((byte)0x00, b[5]);
        assertEquals((byte)0x00, b[6]);
        assertEquals((byte)0x01, b[7]);
        b = XMSSUtil.toBytesBigEndian(1, 10);
        assertEquals(10, b.length);
        assertEquals((byte)0x00, b[0]);
        assertEquals((byte)0x00, b[1]);
        assertEquals((byte)0x00, b[2]);
        assertEquals((byte)0x00, b[3]);
        assertEquals((byte)0x00, b[4]);
        assertEquals((byte)0x00, b[5]);
        assertEquals((byte)0x00, b[6]);
        assertEquals((byte)0x00, b[7]);
        assertEquals((byte)0x00, b[8]);
        assertEquals((byte)0x01, b[9]);
        b = XMSSUtil.toBytesBigEndian(1, 32);
        for (int i = 0; i < 31; i++)
        {
            assertEquals((byte)0x00, b[i]);
        }
        assertEquals((byte)0x01, b[31]);
        b = XMSSUtil.toBytesBigEndian(12345, 9);
        assertEquals(9, b.length);
        assertEquals((byte)0x00, b[0]);
        assertEquals((byte)0x00, b[1]);
        assertEquals((byte)0x00, b[2]);
        assertEquals((byte)0x00, b[3]);
        assertEquals((byte)0x00, b[4]);
        assertEquals((byte)0x00, b[5]);
        assertEquals((byte)0x00, b[6]);
        assertEquals((byte)0x30, b[7]);
        assertEquals((byte)0x39, b[8]);
    }

    public void testLongToBytesBigEndianOffsetException()
    {
        try
        {
            byte[] in = new byte[8];
            Pack.longToBigEndian(1, in, 1);
            fail();
        }
        catch (Exception ex)
        {
        }
    }

    public void testLongToBytesBigEndianOffset()
    {
        byte[] in = new byte[32];
        Pack.longToBigEndian(12345, in, 5);
        assertEquals((byte)0x00, in[0]);
        assertEquals((byte)0x00, in[1]);
        assertEquals((byte)0x00, in[2]);
        assertEquals((byte)0x00, in[3]);
        assertEquals((byte)0x00, in[4]);
        assertEquals((byte)0x00, in[5]);
        assertEquals((byte)0x00, in[6]);
        assertEquals((byte)0x00, in[7]);
        assertEquals((byte)0x00, in[8]);
        assertEquals((byte)0x00, in[9]);
        assertEquals((byte)0x00, in[10]);
        assertEquals((byte)0x30, in[11]);
        assertEquals((byte)0x39, in[12]);
        for (int i = 14; i < in.length; i++)
        {
            assertEquals((byte)0x00, in[i]);
        }
        in = new byte[32];
        Pack.longToBigEndian(12345, in, 24);
        for (int i = 0; i < 24; i++)
        {
            assertEquals((byte)0x00, in[i]);
        }
        assertEquals((byte)0x00, in[28]);
        assertEquals((byte)0x00, in[29]);
        assertEquals((byte)0x30, in[30]);
        assertEquals((byte)0x39, in[31]);
    }

    public void testBytesToIntBigEndianException()
    {
        byte[] in = new byte[4];
        try
        {
            Pack.bigEndianToInt(in, 1);
            fail();
        }
        catch (Exception ex)
        {
        }
    }

    public void testBytesToIntBigEndian()
    {
        byte[] in1 = {0x00, (byte)0xff, 0x00, (byte)0xff};
        int out = Pack.bigEndianToInt(in1, 0);
        assertEquals(16711935, out);
        byte[] in2 = {(byte)0xab, (byte)0xcd, (byte)0xef, (byte)0xaa};
        out = Pack.bigEndianToInt(in2, 0);
        assertEquals("2882400170", new BigInteger(1, in2).toString());
        byte[] in3 = new byte[100];
        Arrays.fill(in3, (byte)0xaa);
        for (int i = 35; i < 39; i++)
        {
            in3[i] = (byte)0xff;
        }
        out = Pack.bigEndianToInt(in3, 35);
        assertEquals(new BigInteger("4294967295"), BigInteger.valueOf(out & 0xffffffffL));
    }

    public void testBytesToLongBigEndianException()
    {
        byte[] in = new byte[10];
        try
        {
            Pack.bigEndianToLong(in, 3);
            fail();
        }
        catch (Exception ex)
        {
        }
    }

    public void testBytesToLongBigEndian()
    {
        byte[] in1 = {0x00, (byte)0xff, 0x00, (byte)0xff, 0x00, (byte)0xff, 0x00, (byte)0xff};
        long out = Pack.bigEndianToLong(in1, 0);
        assertEquals(71777214294589695L, out);
        byte[] in2 = {(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff};
        out = Pack.bigEndianToLong(in2, 0);
        assertEquals("18446744073709551615", new BigInteger(1, in2).toString());
    }

    public void testCalculateTau()
    {
        int height = 10;
        for (int index = 0; index < (1 << 10); index += 2)
        {
            assertEquals(0, XMSSUtil.calculateTau(index, height));
        }
        assertEquals(9, XMSSUtil.calculateTau(511, height));
    }
}
