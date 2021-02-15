package org.bouncycastle.util.encoders.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base32;
import org.bouncycastle.util.encoders.Base32Encoder;
import org.bouncycastle.util.encoders.DecoderException;

public class Base32Test
    extends AbstractCoderTest
{
    // from rfc 4648
    String v1 = "";
    String r1 = "";

    String v2 = "f";
    String r2 = "MY======";

    String v3 = "fo";
    String r3 = "MZXQ====";

    String v4 = "foo";
    String r4 = "MZXW6===";

    String v5 = "foob";
    String r5 = "MZXW6YQ=";

    String v6 = "fooba";
    String r6 = "MZXW6YTB";

    String v7 = "foobar";
    String r7 = "MZXW6YTBOI======";

    private static final String invalid1 = "%O4TYLWG7VjFWdKT8IJcVbZ/jwc=";
    private static final String invalid2 = "F%I4p8Vf/mS+Kxvri3FPoMcqmJ1f";
    private static final String invalid3 = "UJ%EdJYodqHJmd7Rtv6/OP29/jUEFw==";
    private static final String invalid4 = "MO4%yLWG7vjFWdKT8IJcVbZ/jwc=";
    private static final String invalid5 = "UJMEdJYODPHJMd7Rtv6/OP29/jUEF%==";
    private static final String invalid6 = "mO4TyLWG7vjFWdKT8IJcVbZ/jw%=";
    private static final String invalid7 = "F4I4p8Vf/mS+Kxvri3FPoMcqmJ1%";
    private static final String invalid8 = "UJmEdJYodqHJmd7Rtv6/OP29/jUE%c==";
    private static final String invalid9 = "mO4TyLWG7vjFWdKT8IJcVbZ/j%c=";
    private static final String invalida = "F4I4p8Vf/mS+Kxvri3FPoMcqmJ%1";
    private static final String invalidb = "UJmEdJYodqHJmd7Rtv6/OP29/jU%Fc==";
    private static final String invalidc = "mO4TyLWG7vjFWdKT8IJcVbZ/%wc=";
    private static final String invalidd = "F4I4P8VfXMSZKXVRI3FPOMCQM%2C";
    private static final String invalide = "UJmEdJYodqHJmd7Rtv6/OP29/jUEFw=1";
    private static final String invalidf = "DAXFSKJDQSBTYW";
    private static final String invalidg = "M";

    public Base32Test(
        String    name)
    {
        super(name);
    }
    
    protected void setUp()
    {
        super.setUp();
        enc = new Base32Encoder();
    }

    public void testSamples()
        throws IOException
    {
        assertTrue(Arrays.areEqual(Strings.toByteArray(r1), Base32.encode(Strings.toByteArray(v1))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r2), Base32.encode(Strings.toByteArray(v2))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r3), Base32.encode(Strings.toByteArray(v3))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r4), Base32.encode(Strings.toByteArray(v4))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r5), Base32.encode(Strings.toByteArray(v5))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r6), Base32.encode(Strings.toByteArray(v6))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r7), Base32.encode(Strings.toByteArray(v7))));

        assertTrue(Arrays.areEqual(Strings.toByteArray(v1), Base32.decode(r1)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v2), Base32.decode(r2)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v3), Base32.decode(r3)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v4), Base32.decode(r4)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v5), Base32.decode(r5)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v6), Base32.decode(r6)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v7), Base32.decode(r7)));
    }

    public void testInvalidInput()
        throws IOException
    {
        String[] invalid = new String[] {
            invalid1, invalid2, invalid3, invalid4, invalid5, invalid6, invalid7, invalid8,
            invalid9, invalida, invalidb, invalidc, invalidd, invalide, invalidf, invalidg };

        for (int i = 0; i != invalid.length; i++)
        {
            invalidTest(invalid[i]);
            invalidTest(Strings.toByteArray(invalid[i]));
        }
    }

    public void testWithWhitespace()
        throws Exception
    {
        String data = "ORSXG5DTORZG" + "\r\n" + "               " + "S3TH";

        assertTrue(Arrays.areEqual(Strings.toByteArray("teststring"), Base32.decode(data)));

        byte[] bData = Strings.toByteArray(data);
        assertTrue(Arrays.areEqual(Strings.toByteArray("teststring"), Base32.decode(bData)));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        Base32.decode(Arrays.concatenate(new byte[4], bData), 4, bData.length, bOut);

        assertTrue(Arrays.areEqual(Strings.toByteArray("teststring"), bOut.toByteArray()));
    }

    private void invalidTest(String data)
    {
        try
        {
            Base32.decode(data);
        }
        catch (DecoderException e)
        {
            return;
        }

        fail("invalid String data parsed");
    }

    private void invalidTest(byte[] data)
    {
        try
        {
            Base32.decode(data);
        }
        catch (DecoderException e)
        {
            return;
        }

        fail("invalid byte data parsed");
    }

    protected char paddingChar()
    {
        return '=';
    }

    protected boolean isEncodedChar(char c)
    {
        return "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c) >= 0;
    }
}
