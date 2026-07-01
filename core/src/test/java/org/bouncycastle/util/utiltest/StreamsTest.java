package org.bouncycastle.util.utiltest;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class StreamsTest
    extends TestCase
{
    public void testReadLenBytesFully()
        throws IOException
    {
        // exact length, spanning multiple internal read chunks (length > the internal buffer size)
        byte[] data = new byte[10000];
        for (int i = 0; i != data.length; i++)
        {
            data[i] = (byte)i;
        }

        byte[] read = Streams.readLenBytesFully(new ByteArrayInputStream(data), data.length);
        assertTrue(Arrays.areEqual(data, read));

        // a prefix shorter than the available data is read exactly
        byte[] prefix = Streams.readLenBytesFully(new ByteArrayInputStream(data), 100);
        assertEquals(100, prefix.length);
        assertTrue(Arrays.areEqual(Arrays.copyOf(data, 100), prefix));
    }

    public void testReadLenBytesFullyZeroLength()
        throws IOException
    {
        byte[] read = Streams.readLenBytesFully(new ByteArrayInputStream(new byte[]{ 1, 2, 3 }), 0);
        assertEquals(0, read.length);
    }

    public void testReadLenBytesFullyPartialReads()
        throws IOException
    {
        // a stream that yields one byte per read call must still be fully assembled
        byte[] data = new byte[1000];
        for (int i = 0; i != data.length; i++)
        {
            data[i] = (byte)(i * 7);
        }

        byte[] read = Streams.readLenBytesFully(new OneByteAtATimeInputStream(data), data.length);
        assertTrue(Arrays.areEqual(data, read));
    }

    public void testReadLenBytesFullyShortStreamThrows()
    {
        try
        {
            Streams.readLenBytesFully(new ByteArrayInputStream(new byte[10]), 20);
            fail("no exception");
        }
        catch (EOFException e)
        {
            assertEquals("premature end of stream", e.getMessage());
        }
        catch (IOException e)
        {
            fail("wrong exception: " + e);
        }
    }

    public void testReadLenBytesFullyHostileLengthDoesNotOverAllocate()
    {
        // A declared length far larger than the data available must fail fast with an EOFException
        // rather than pre-allocating new byte[Integer.MAX_VALUE] (the github #2338 DoS class): the
        // call returns promptly without an OutOfMemoryError because allocation tracks delivered bytes.
        try
        {
            Streams.readLenBytesFully(new ByteArrayInputStream(new byte[10]), Integer.MAX_VALUE);
            fail("no exception");
        }
        catch (EOFException e)
        {
            assertEquals("premature end of stream", e.getMessage());
        }
        catch (IOException e)
        {
            fail("wrong exception: " + e);
        }
    }

    public void testReadLenBytesFullyNegativeLength()
        throws IOException
    {
        try
        {
            Streams.readLenBytesFully(new ByteArrayInputStream(new byte[10]), -1);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("len cannot be negative", e.getMessage());
        }
    }

    private static class OneByteAtATimeInputStream
        extends InputStream
    {
        private final byte[] data;
        private int pos = 0;

        OneByteAtATimeInputStream(byte[] data)
        {
            this.data = data;
        }

        public int read()
        {
            return pos >= data.length ? -1 : (data[pos++] & 0xff);
        }

        public int read(byte[] b, int off, int len)
        {
            if (pos >= data.length)
            {
                return -1;
            }
            if (len <= 0)
            {
                return 0;
            }
            b[off] = data[pos++];
            return 1;  // deliberately one byte per call to exercise the accumulation loop
        }
    }
}
