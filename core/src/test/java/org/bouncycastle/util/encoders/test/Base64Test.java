package org.bouncycastle.util.encoders.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;

public class Base64Test extends AbstractCoderTest
{
    private static final String sample1 = "mO4TyLWG7vjFWdKT8IJcVbZ/jwc=";
    private static final byte[] sample1Bytes = Hex.decode("98ee13c8b586eef8c559d293f0825c55b67f8f07");
    private static final String sample2 = "F4I4p8Vf/mS+Kxvri3FPoMcqmJ1f";
    private static final byte[] sample2Bytes = Hex.decode("178238a7c55ffe64be2b1beb8b714fa0c72a989d5f");
    private static final String sample3 = "UJmEdJYodqHJmd7Rtv6/OP29/jUEFw==";
    private static final byte[] sample3Bytes = Hex.decode("50998474962876a1c999ded1b6febf38fdbdfe350417");

    private static final String invalid1 = "%O4TyLWG7vjFWdKT8IJcVbZ/jwc=";
    private static final String invalid2 = "F%I4p8Vf/mS+Kxvri3FPoMcqmJ1f";
    private static final String invalid3 = "UJ%EdJYodqHJmd7Rtv6/OP29/jUEFw==";
    private static final String invalid4 = "mO4%yLWG7vjFWdKT8IJcVbZ/jwc=";
    private static final String invalid5 = "UJmEdJYodqHJmd7Rtv6/OP29/jUEF%==";
    private static final String invalid6 = "mO4TyLWG7vjFWdKT8IJcVbZ/jw%=";
    private static final String invalid7 = "F4I4p8Vf/mS+Kxvri3FPoMcqmJ1%";
    private static final String invalid8 = "UJmEdJYodqHJmd7Rtv6/OP29/jUE%c==";
    private static final String invalid9 = "mO4TyLWG7vjFWdKT8IJcVbZ/j%c=";
    private static final String invalida = "F4I4p8Vf/mS+Kxvri3FPoMcqmJ%1";
    private static final String invalidb = "UJmEdJYodqHJmd7Rtv6/OP29/jU%Fc==";
    private static final String invalidc = "mO4TyLWG7vjFWdKT8IJcVbZ/%wc=";
    private static final String invalidd = "F4I4p8Vf/mS+Kxvri3FPoMcqm%1c";
    private static final String invalide = "UJmEdJYodqHJmd7Rtv6/OP29/jUEFw=1";
    private static final String invalidf = "DAxFSkJDQSBTYW";
    private static final String invalidg = "M";

    public Base64Test(
        String    name)
    {
        super(name);
    }
    
    protected void setUp()
    {
        super.setUp();
        enc = new Base64Encoder();
    }

    public void testSamples()
        throws IOException
    {
        assertTrue(Arrays.areEqual(new byte[0], Base64.decode("")));
        assertEquals(0, Base64.decode(new byte[0], 0, 0, new ByteArrayOutputStream()));
        assertTrue(Arrays.areEqual(Strings.toByteArray("1"), Base64.decode("MQ==")));
        assertTrue(Arrays.areEqual(sample1Bytes, Base64.decode(sample1)));
        assertTrue(Arrays.areEqual(sample1Bytes, Base64.decode(Strings.toByteArray(sample1))));
        assertTrue(Arrays.areEqual(sample2Bytes, Base64.decode(sample2)));
        assertTrue(Arrays.areEqual(sample2Bytes, Base64.decode(Strings.toByteArray(sample2))));
        assertTrue(Arrays.areEqual(sample3Bytes, Base64.decode(sample3)));
        assertTrue(Arrays.areEqual(sample3Bytes, Base64.decode(Strings.toByteArray(sample3))));
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
        String data = "dGVzdHN0cmluZ" + "\r\n" + "               " + "w==";

        assertTrue(Arrays.areEqual(Strings.toByteArray("teststring"), Base64.decode(data)));

        byte[] bData = Strings.toByteArray(data);
        assertTrue(Arrays.areEqual(Strings.toByteArray("teststring"), Base64.decode(bData)));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        Base64.decode(Arrays.concatenate(new byte[4], bData), 4, bData.length, bOut);

        assertTrue(Arrays.areEqual(Strings.toByteArray("teststring"), bOut.toByteArray()));
    }

    private void invalidTest(String data)
    {
        try
        {
            Base64.decode(data);
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
            Base64.decode(data);
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
        if (Character.isLetterOrDigit(c))
        {
            return true;
        }
        else if (c == '+')
        {
            return true;
        }
        else if (c == '/')
        {
            return true;
        }
        return false;
    }

}
