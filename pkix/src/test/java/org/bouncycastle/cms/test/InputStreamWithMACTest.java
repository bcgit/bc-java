package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.cms.InputStreamWithMAC;

public class InputStreamWithMACTest
    extends TestCase
{
    public static void main(String[] args)
        throws IOException
    {
        InputStreamWithMACTest test = new InputStreamWithMACTest();
       // test.testRead();
        test.testReadBlock();
    }

    public static Test suite()
        throws Exception
    {
        return new CMSTestSetup(new TestSuite(InputStreamWithMACTest.class));
    }

//    public void testRead()
//        throws IOException
//    {
//        byte[] array = new byte[Integer.MAX_VALUE - 16];
//        InputStreamWithMAC inputStream = new InputStreamWithMAC(new ByteArrayInputStream(array), new byte[16]);
//        while (inputStream.read() != -1) ;
//    }

    public void testReadBlock()
        throws IOException
    {
        byte[] array = new byte[32];
        byte[] mac = new byte[]{
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1};
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
        assertEquals(1, inputStream.read(new byte[1], 0, 1));
        assertEquals(1, inputStream.read(new byte[1], 0, 1));
        assertEquals(14, inputStream.read(new byte[17], 0, 17));
        inputStream = new InputStreamWithMAC(new ByteArrayInputStream(array), mac);
        assertEquals(32, inputStream.read(new byte[46], 0, 46));
        assertEquals(16, inputStream.read(new byte[17], 0, 17));
        assertEquals(-1, inputStream.read(new byte[17], 0, 17));
        assertEquals(-1, inputStream.read());
    }
}
