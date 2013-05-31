package org.bouncycastle.util.encoders.test;

import java.io.IOException;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.encoders.HexEncoder;

public class HexTest extends AbstractCoderTest
{
    private static final String invalid1 = "%O4T";
    private static final String invalid2 = "FZI4";
    private static final String invalid3 = "ae%E";
    private static final String invalid4 = "fO4%";
    private static final String invalid5 = "beefe";
    private static final String invalid6 = "beefs";

    public HexTest(
        String    name)
    {
        super(name);
    }
    
    protected void setUp()
    {
        super.setUp();
        enc = new HexEncoder();
    }

    protected char paddingChar()
    {
        return 0;
    }

    protected boolean isEncodedChar(char c)
    {
        if ('A' <= c && c <= 'F')
        {
            return true;
        } 
        if ('a' <= c && c <= 'f')
        {
            return true;
        } 
        if ('0' <= c && c <= '9')
        {
            return true;
        } 
        return false;
    }

    public void testInvalidInput()
        throws IOException
    {
        String[] invalid = new String[] { invalid1, invalid2, invalid3, invalid4, invalid5, invalid6 };

        for (int i = 0; i != invalid.length; i++)
        {
            invalidTest(invalid[i]);
            invalidTest(Strings.toByteArray(invalid[i]));
        }
    }

    private void invalidTest(String data)
    {
        try
        {
            Hex.decode(data);
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
            Hex.decode(data);
        }
        catch (DecoderException e)
        {
            return;
        }

        fail("invalid byte data parsed");
    }
}
