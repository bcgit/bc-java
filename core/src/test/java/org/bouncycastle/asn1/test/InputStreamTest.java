package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.util.test.SimpleTest;

public class InputStreamTest 
    extends SimpleTest
{
    private static final byte[] outOfBoundsLength = new byte[] { (byte)0x30, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff };
    private static final byte[] negativeLength = new byte[] { (byte)0x30, (byte)0x84, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff };
    private static final byte[] outsideLimitLength = new byte[] { (byte)0x30, (byte)0x83, (byte)0x0f, (byte)0xff, (byte)0xff };
    
    
    public String getName()
    {
        return "InputStream";
    }
    
    public void performTest() 
        throws Exception
    {
        ASN1InputStream aIn = new ASN1InputStream(outOfBoundsLength);
        
        try
        {
            aIn.readObject();
            fail("out of bounds length not detected.");
        }
        catch (IOException e)
        {
            if (!e.getMessage().startsWith("DER length more than 4 bytes"))
            {
                fail("wrong exception: " + e.getMessage());
            }
        }
        
        aIn = new ASN1InputStream(negativeLength);
        
        try
        {
            aIn.readObject();
            fail("negative length not detected.");
        }
        catch (IOException e)
        {
            if (!e.getMessage().equals("corrupted stream - negative length found"))
            {
                fail("wrong exception: " + e.getMessage());
            }
        }
        
        aIn = new ASN1InputStream(outsideLimitLength);
        
        try
        {
            aIn.readObject();
            fail("outside limit length not detected.");
        }
        catch (IOException e)
        {
            if (!e.getMessage().equals("corrupted stream - out of bounds length found"))
            {
                fail("wrong exception: " + e.getMessage());
            }
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new InputStreamTest());
    }
}
