package org.bouncycastle.util.io.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.util.io.BufferingOutputStream;
import org.bouncycastle.util.test.SimpleTest;

public class BufferingOutputStreamTest
    extends SimpleTest
{
    public String getName()
    {
        return "BufferingStreamTest";
    }

    public void performTest()
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        for (int i = 1; i != 256; i++)
        {
            byte[] data = new byte[i];

            random.nextBytes(data);

            checkStream(data, 16);
            checkStream(data, 33);
            checkStream(data, 128);
        }
    }

    private void checkStream(byte[] data, int bufsize)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BufferingOutputStream bfOut = new BufferingOutputStream(bOut, bufsize);

        for (int i = 0; i != 10; i++)
        {
            bfOut.write(data[0]);
            bfOut.write(data, 1, data.length - 1);
        }

        bfOut.close();

        byte[] output = bOut.toByteArray();

        for (int i = 0; i != 10; i++)
        {
             for (int j = 0; j != data.length; j++)
             {
                 if (output[i * data.length + j] != data[j])
                 {
                     fail("data mismatch!");
                 }
             }
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new BufferingOutputStreamTest());
    }
}
