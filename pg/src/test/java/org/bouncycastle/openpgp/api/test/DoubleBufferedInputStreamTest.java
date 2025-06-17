package org.bouncycastle.openpgp.api.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.api.DoubleBufferedInputStream;
import org.bouncycastle.util.io.Streams;

public class DoubleBufferedInputStreamTest
    extends AbstractPacketTest
{

    @Override
    public String getName()
    {
        return "RetainingInputStreamTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        throwWhileReadingNthBlock();
        successfullyReadSmallerThanBuffer();
        successfullyReadGreaterThanBuffer();

        throwWhileReadingFirstBlock();
        throwWhileClosing();
    }

    private void successfullyReadSmallerThanBuffer()
        throws IOException
    {
        byte[] bytes = getSequentialBytes(400);
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        DoubleBufferedInputStream<ByteArrayInputStream> retIn = new DoubleBufferedInputStream<ByteArrayInputStream>(bIn, 512);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        Streams.pipeAll(retIn, bOut);
        isEncodingEqual(bytes, bOut.toByteArray());
    }

    private void successfullyReadGreaterThanBuffer()
        throws IOException
    {
        byte[] bytes = getSequentialBytes(2000);
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        DoubleBufferedInputStream<ByteArrayInputStream> retIn = new DoubleBufferedInputStream<ByteArrayInputStream>(bIn, 512);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        Streams.pipeAll(retIn, bOut);
        isEncodingEqual(bytes, bOut.toByteArray());
    }

    private void throwWhileReadingFirstBlock()
    {
        InputStream throwAfterNBytes = new InputStream()
        {
            int throwAt = 314;
            int r = 0;

            @Override
            public int read()
                throws IOException
            {
                int i = r;
                if (r == throwAt)
                {
                    throw new IOException("Oopsie");
                }
                r++;
                return i;
            }
        };
        DoubleBufferedInputStream<InputStream> retIn = new DoubleBufferedInputStream<InputStream>(throwAfterNBytes, 512);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        try
        {
            Streams.pipeAll(retIn, bOut);
        }
        catch (IOException e)
        {
            isEquals("Oopsie", e.getMessage());
        }
        isEquals("throwWhileReadingFirstBlock: expected no bytes emitted", 0, bOut.toByteArray().length);
    }

    private void throwWhileReadingNthBlock()
    {
        InputStream throwAfterNBytes = new InputStream()
        {
            int throwAt = 10;
            int r = 0;

            @Override
            public int read()
                throws IOException
            {
                int i = r;
                if (r == throwAt)
                {
                    throw new IOException("Oopsie");
                }
                r++;
                return i;
            }
        };
        DoubleBufferedInputStream<InputStream> retIn = new DoubleBufferedInputStream<InputStream>(throwAfterNBytes, 4);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        try
        {
            Streams.pipeAll(retIn, bOut);
        }
        catch (IOException e)
        {
            isEquals("Oopsie", e.getMessage());
        }
        byte[] got = bOut.toByteArray();
        isEquals("throwWhileReadingNthBlock: expected 4 bytes emitted. Got " + got.length, 4, got.length);
    }

    private void throwWhileClosing()
    {
        byte[] bytes = getSequentialBytes(100);
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        FilterInputStream throwOnClose = new FilterInputStream(bIn)
        {
            @Override
            public void close()
                throws IOException
            {
                throw new IOException("Oopsie");
            }
        };
        DoubleBufferedInputStream<FilterInputStream> retIn = new DoubleBufferedInputStream<FilterInputStream>(throwOnClose, 512);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        try
        {
            Streams.pipeAll(retIn, bOut);
        }
        catch (IOException e)
        {
            isEquals("Oopsie", e.getMessage());
        }
        isEquals("throwWhileClosing: len mismatch", 0, bOut.toByteArray().length);
    }

    private byte[] getSequentialBytes(int n)
    {
        byte[] bytes = new byte[n];
        for (int i = 0; i < bytes.length; i++)
        {
            bytes[i] = (byte)(i % 128);
        }
        return bytes;
    }

    public static void main(String[] args)
    {
        runTest(new DoubleBufferedInputStreamTest());
    }
}
