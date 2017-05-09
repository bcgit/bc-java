package org.bouncycastle.kmip.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.kmip.wire.KMIPBigInteger;
import org.bouncycastle.kmip.wire.KMIPBoolean;
import org.bouncycastle.kmip.wire.KMIPByteString;
import org.bouncycastle.kmip.wire.KMIPDateTime;
import org.bouncycastle.kmip.wire.KMIPEncodable;
import org.bouncycastle.kmip.wire.KMIPEnumeration;
import org.bouncycastle.kmip.wire.KMIPInteger;
import org.bouncycastle.kmip.wire.KMIPInterval;
import org.bouncycastle.kmip.wire.KMIPItem;
import org.bouncycastle.kmip.wire.KMIPLong;
import org.bouncycastle.kmip.wire.KMIPStructure;
import org.bouncycastle.kmip.wire.KMIPTextString;
import org.bouncycastle.kmip.wire.binary.BinaryEncoder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class BasicBinTest
    extends TestCase
{
    public void testInteger()
        throws Exception
    {
        KMIPInteger obj = new KMIPInteger(0x420020, 8);

        check(obj, Hex.decode("42002002000000040000000800000000"));
    }

    public void testLong()
        throws Exception
    {
        KMIPLong obj = new KMIPLong(0x420020, 123456789000000000L);

        check(obj, Hex.decode("420020030000000801b69b4ba5749200"));
    }

    public void testBigInteger()
        throws Exception
    {
        KMIPBigInteger obj = new KMIPBigInteger(0x420020, new BigInteger("1234567890000000000000000000"));

        check(obj, Hex.decode("42002004000000100000000003fd35eb6bc2df4618080000"));
    }

    public void testEnumeration()
        throws Exception
    {
        KMIPEnumeration obj = new KMIPEnumeration(0x420020, 255);

        check(obj, Hex.decode("4200200500000004000000ff00000000"));
    }

    public void testBoolean()
        throws Exception
    {
        KMIPBoolean obj = new KMIPBoolean(0x420020, true);

        check(obj, Hex.decode("42002006000000080000000000000001"));

        obj = new KMIPBoolean(0x420020, false);

        check(obj, Hex.decode("42002006000000080000000000000000"));
    }

    public void testTextString()
        throws Exception
    {
        KMIPTextString obj = new KMIPTextString(0x420020, "Hello World");

        check(obj, Hex.decode("420020070000000b48656c6c6f20576f726c640000000000"));
    }

    public void testByteString()
        throws Exception
    {
        KMIPByteString obj = new KMIPByteString(0x420020, new byte[] { 0x01, 0x02, 0x3 });

        check(obj, Hex.decode("42002008000000030102030000000000"));
    }

    public void testDateTime()
        throws Exception
    {
        KMIPDateTime obj = new KMIPDateTime(0x420020, new Date(0x47da67f8L));

        check(obj, Hex.decode("42002009000000080000000047da67f8"));
    }

    public void testInterval()
        throws Exception
    {
        KMIPInterval obj = new KMIPInterval(0x420020, 10 * 24 * 60 * 60);

        check(obj, Hex.decode("4200200a00000004000d2f0000000000"));
    }

    public void testStructure()
        throws Exception
    {
        KMIPStructure obj = new KMIPStructure(0x420020, new KMIPItem[] { new KMIPEnumeration(0x420004, 254), new KMIPInteger(0x420005, 255) });

        check(obj, Hex.decode("42002001000000204200040500000004000000FE000000004200050200000004000000FF00000000"));
    }

    private void check(KMIPEncodable obj, byte[] expected)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        BinaryEncoder bEnc = new BinaryEncoder(bOut);

        bEnc.output(obj);

        assertTrue(Arrays.areEqual(expected, bOut.toByteArray()));
    }
}
