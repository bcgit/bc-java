package org.bouncycastle.tls.test;

import junit.framework.TestCase;
import org.bouncycastle.tls.ByteQueueInputStream;
import org.bouncycastle.util.Arrays;

public class ByteQueueInputStreamTest
    extends TestCase
{
    public void testAvailable()
    {
        ByteQueueInputStream in = new ByteQueueInputStream();

        // buffer is empty
        assertEquals(0, in.available());

        // after adding once
        in.addBytes(new byte[10]);
        assertEquals(10, in.available());

        // after adding more than once
        in.addBytes(new byte[5]);
        assertEquals(15, in.available());

        // after reading a single byte
        in.read();
        assertEquals(14, in.available());

        // after reading into a byte array
        in.read(new byte[4]);
        assertEquals(10, in.available());

        in.close();// so Eclipse doesn't whine about a resource leak
    }

    public void testSkip()
    {
        ByteQueueInputStream in = new ByteQueueInputStream();

        // skip when buffer is empty
        assertEquals(0, in.skip(10));

        // skip equal to available
        in.addBytes(new byte[2]);
        assertEquals(2, in.skip(2));
        assertEquals(0, in.available());

        // skip less than available
        in.addBytes(new byte[10]);
        assertEquals(5, in.skip(5));
        assertEquals(5, in.available());

        // skip more than available
        assertEquals(5, in.skip(20));
        assertEquals(0, in.available());

        in.close();// so Eclipse doesn't whine about a resource leak
    }

    public void testRead()
    {
        ByteQueueInputStream in = new ByteQueueInputStream();
        in.addBytes(new byte[]{ 0x01, 0x02 });
        in.addBytes(new byte[]{ 0x03 });

        assertEquals(0x01, in.read());
        assertEquals(0x02, in.read());
        assertEquals(0x03, in.read());
        assertEquals(-1, in.read());

        in.close();// so Eclipse doesn't whine about a resource leak
    }

    public void testReadArray()
    {
        ByteQueueInputStream in = new ByteQueueInputStream();
        in.addBytes(new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });

        byte[] buffer = new byte[5];

        // read less than available into specified position
        assertEquals(1, in.read(buffer, 2, 1));
        assertArrayEquals(new byte[]{ 0x00, 0x00, 0x01, 0x00, 0x00 }, buffer);

        // read equal to available
        assertEquals(5, in.read(buffer));
        assertArrayEquals(new byte[]{ 0x02, 0x03, 0x04, 0x05, 0x06 }, buffer);

        // read more than available
        in.addBytes(new byte[]{ 0x01, 0x02, 0x03 });
        assertEquals(3, in.read(buffer));
        assertArrayEquals(new byte[]{ 0x01, 0x02, 0x03, 0x05, 0x06 }, buffer);

        in.close();// so Eclipse doesn't whine about a resource leak
    }

    public void testPeek()
    {
        ByteQueueInputStream in = new ByteQueueInputStream();

        byte[] buffer = new byte[5];

        // peek more than available
        assertEquals(0, in.peek(buffer));
        assertArrayEquals(new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00 }, buffer);

        // peek less than available
        in.addBytes(new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 });
        assertEquals(5, in.peek(buffer));
        assertArrayEquals(new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05 }, buffer);
        assertEquals(6, in.available());

        // peek equal to available
        in.read();
        assertEquals(5, in.peek(buffer));
        assertArrayEquals(new byte[]{ 0x02, 0x03, 0x04, 0x05, 0x06 }, buffer);
        assertEquals(5, in.available());

        in.close();// so Eclipse doesn't whine about a resource leak
    }

    private static void assertArrayEquals(byte[] a, byte[] b)
    {
        assertTrue(Arrays.areEqual(a, b));
    }
}
