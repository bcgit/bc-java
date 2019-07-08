package org.bouncycastle.asn1.test;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ASN1IntegerTest
    extends SimpleTest
{
    private static final byte[] suspectKey = Base64.decode(
        "MIGJAoGBAHNc+iExm94LUrJdPSJ4QJ9tDRuvaNmGVHpJ4X7a5zKI02v+2E7RotuiR2MHDJfVJkb9LUs2kb3XBlyENhtMLsbeH+3Muy3" +
            "hGDlh/mLJSh1s4c5jDKBRYOHom7Uc8wP0P2+zBCA+OEdikNDFBaP5PbR2Xq9okG2kPh35M2quAiMTAgMBAAE=");

    public String getName()
    {
        return "ASN1Integer";
    }

    public void performTest()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "true");

        ASN1Sequence.getInstance(suspectKey);

        testValidEncodingSingleByte();
        testValidEncodingMultiByte();
        testInvalidEncoding_00();
        testInvalidEncoding_ff();
        testInvalidEncoding_00_32bits();
        testInvalidEncoding_ff_32bits();
        //testLooseInvalidValidEncoding_FF_32B();
        //testLooseInvalidValidEncoding_zero_32B();
        testLooseValidEncoding_zero_32BAligned();
        testLooseValidEncoding_FF_32BAligned();
        testLooseValidEncoding_FF_32BAligned_1not0();
        testLooseValidEncoding_FF_32BAligned_2not0();
        testOversizedEncoding();
        
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "true");

        new ASN1Integer(Hex.decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

        new ASN1Enumerated(Hex.decode("005a47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        
        try
        {
            new ASN1Integer(Hex.decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b"));

            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }

        isTrue(!Properties.setThreadOverride("org.bouncycastle.asn1.allow_unsafe_integer", true));
        
        new ASN1Integer(Hex.decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b"));

        isTrue(Properties.removeThreadOverride("org.bouncycastle.asn1.allow_unsafe_integer"));

        try
        {
            ASN1Sequence.getInstance(suspectKey);

            fail("no exception");
        }
        catch (IllegalArgumentException e)
        { 
            isEquals("test 1", "failed to construct sequence from byte[]: corrupted stream detected", e.getMessage());
        }

        try
        {
            new ASN1Integer(Hex.decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }

        try
        {
            new ASN1Enumerated(Hex.decode("ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed enumerated", e.getMessage());
        }

        try
        {
            new ASN1Enumerated(Hex.decode("005a47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e"));

            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed enumerated", e.getMessage());
        }
    }

    /**
     * Ensure existing single byte behavior.
     */
    public void testValidEncodingSingleByte()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Without property, single byte.
        //
        byte[] rawInt = Hex.decode("10");
        ASN1Integer i = new ASN1Integer(rawInt);
        isEquals(i.getValue().intValue(), 16);
        isEquals(i.intValueExact(), 16);

        //
        // With property set.
        //
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "true");

        rawInt = Hex.decode("10");
        i = new ASN1Integer(rawInt);
        isEquals(i.getValue().intValue(), 16);
        isEquals(i.intValueExact(), 16);
    }

    public void testValidEncodingMultiByte()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Without property, single byte.
        //
        byte[] rawInt = Hex.decode("10FF");
        ASN1Integer i = new ASN1Integer(rawInt);
        isEquals(i.getValue().intValue(), 4351);
        isEquals(i.intValueExact(), 4351);

        //
        // With property set.
        //
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "true");

        rawInt = Hex.decode("10FF");
        i = new ASN1Integer(rawInt);
        isEquals(i.getValue().intValue(), 4351);
        isEquals(i.intValueExact(), 4351);
    }

    public void testInvalidEncoding_00()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        try
        {
            byte[] rawInt = Hex.decode("0010FF");
            new ASN1Integer(rawInt);
            fail("Expecting illegal argument exception.");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }

    public void testInvalidEncoding_ff()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        try
        {
            byte[] rawInt = Hex.decode("FF81FF");
            new ASN1Integer(rawInt);
            fail("Expecting illegal argument exception.");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }

    public void testInvalidEncoding_00_32bits()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Check what would pass loose validation fails outside of loose validation.
        //
        try
        {
            byte[] rawInt = Hex.decode("0000000010FF");
            new ASN1Integer(rawInt);
            fail("Expecting illegal argument exception.");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }

    public void testInvalidEncoding_ff_32bits()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Check what would pass loose validation fails outside of loose validation.
        //
        try
        {
            byte[] rawInt = Hex.decode("FFFFFFFF01FF");
            new ASN1Integer(rawInt);
            fail("Expecting illegal argument exception.");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }

    /*
     Unfortunately it turns out that integers stored without sign bits that are assumed to be
     unsigned.. this means a string of FF may occur and then the user will call getPositiveValue().
     Sigh..
    public void testLooseInvalidValidEncoding_zero_32B()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should still fail as loose validation only permits 3 leading 0x00 bytes.
        //
        try
        {
            System.getProperties().put("org.bouncycastle.asn1.allow_unsafe_integer", "true");
            byte[] rawInt = Hex.decode("0000000010FF");
            ASN1Integer i = new ASN1Integer(rawInt);
            fail("Expecting illegal argument exception.");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }

    public void testLooseInvalidValidEncoding_FF_32B()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should still fail as loose validation only permits 3 leading 0xFF bytes.
        //
        try
        {
            System.getProperties().put("org.bouncycastle.asn1.allow_unsafe_integer", "true");
            byte[] rawInt = Hex.decode("FFFFFFFF10FF");
            ASN1Integer i = new ASN1Integer(rawInt);
            fail("Expecting illegal argument exception.");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }
    */

    public void testLooseValidEncoding_zero_32BAligned()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should pass as loose validation permits 3 leading 0x00 bytes.
        //

        System.getProperties().put("org.bouncycastle.asn1.allow_unsafe_integer", "true");
        byte[] rawInt = Hex.decode("00000010FF000000");
        ASN1Integer i = new ASN1Integer(rawInt);
        isEquals(72997666816L, BigIntegers.longValueExact(i.getValue()));
    }

    public void testLooseValidEncoding_FF_32BAligned()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should pass as loose validation permits 3

        System.getProperties().put("org.bouncycastle.asn1.allow_unsafe_integer", "true");
        byte[] rawInt = Hex.decode("FFFFFF10FF000000");
        ASN1Integer i = new ASN1Integer(rawInt);
        isEquals(-1026513960960L, BigIntegers.longValueExact(i.getValue()));
    }

    public void testLooseValidEncoding_FF_32BAligned_1not0()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should pass as loose validation permits 3 leading 0xFF bytes.
        //

        System.getProperties().put("org.bouncycastle.asn1.allow_unsafe_integer", "true");
        byte[] rawInt = Hex.decode("FFFEFF10FF000000");
        ASN1Integer i = new ASN1Integer(rawInt);
        isEquals(-282501490671616L, BigIntegers.longValueExact(i.getValue()));
    }

    public void testLooseValidEncoding_FF_32BAligned_2not0()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should pass as loose validation permits 3 leading 0xFF bytes.
        //

        System.getProperties().put("org.bouncycastle.asn1.allow_unsafe_integer", "true");
        byte[] rawInt = Hex.decode("FFFFFE10FF000000");
        ASN1Integer i = new ASN1Integer(rawInt);
        isEquals(-2126025588736L, BigIntegers.longValueExact(i.getValue()));
    }

    public void testOversizedEncoding()
        throws Exception
    {
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "false");
        //
        // Should pass as loose validation permits 3 leading 0xFF bytes.
        //

        System.getProperties().put("org.bouncycastle.asn1.allow_unsafe_integer", "true");
        byte[] rawInt = Hex.decode("FFFFFFFE10FF000000000000");
        ASN1Integer i = new ASN1Integer(rawInt);
        isEquals(new BigInteger(Hex.decode("FFFFFFFE10FF000000000000")), i.getValue());

        rawInt = Hex.decode("FFFFFFFFFE10FF000000000000");
        try
        {
            new ASN1Integer(rawInt);
        }
        catch (IllegalArgumentException e)
        {
            isEquals("malformed integer", e.getMessage());
        }
    }

    public static void main(
        String[] args)
    {
        runTest(new ASN1IntegerTest());
    }
}
