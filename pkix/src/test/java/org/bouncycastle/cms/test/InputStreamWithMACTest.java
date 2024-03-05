package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.cms.InputStreamWithMAC;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class InputStreamWithMACTest
    extends TestCase
{
    public static void main(String[] args)
        throws IOException
    {
        InputStreamWithMACTest test = new InputStreamWithMACTest();

        test.testReadBlock();
    }

    public static Test suite()
        throws Exception
    {
        return new CMSTestSetup(new TestSuite(InputStreamWithMACTest.class));
    }

    public void testReadBlock()
        throws IOException
    {
        byte[] array = new byte[32];
        byte[] mac = Hex.decode("0102030405060708090a0b0c0d0e0f10");
        InputStreamWithMAC inputStream = new InputStreamWithMAC(new ByteArrayInputStream(array), mac);
        try
        {
            inputStream.getMAC();
        }
        catch (IllegalStateException e)
        {
            assertEquals("input stream not fully processed", e.getMessage());
        }
        assertEquals(32, inputStream.read(new byte[46], 0, 46));
        byte[] tailBytes = new byte[19];
        assertEquals(1, inputStream.read(tailBytes, 0, 1));
        assertEquals(1, inputStream.read(tailBytes, 1, 1));
        assertEquals(14, inputStream.read(tailBytes, 2, 17));
        assertEquals(-1, inputStream.read());
        assertTrue(Arrays.areEqual(inputStream.getMAC(), mac));
        assertTrue(Arrays.areEqual(inputStream.getMAC(), Arrays.copyOfRange(tailBytes, 0, 16)));

        inputStream = new InputStreamWithMAC(new ByteArrayInputStream(array), mac);
        assertEquals(32, inputStream.read(new byte[46], 0, 46));
        tailBytes = new byte[17];
        assertEquals(16, inputStream.read(tailBytes, 0, 17));
        assertTrue(Arrays.areEqual(inputStream.getMAC(), Arrays.copyOfRange(tailBytes, 0, 16)));
        assertEquals(-1, inputStream.read(new byte[17], 0, 17));
        assertEquals(-1, inputStream.read());
    }
}
