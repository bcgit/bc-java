package org.bouncycastle.gpg.keybox;

import java.io.IOException;
import java.security.Security;
import java.util.Arrays;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class KeyBoxByteBufferTest
    extends SimpleTest
{

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new KeyBoxByteBufferTest());
    }

    public void testReadPastEnd()
        throws Exception
    {
        byte[] expected = new byte[]{1, 2, 3};

        KeyBoxByteBuffer buf = KeyBoxByteBuffer.wrap(expected);
        try
        {
            buf.bN(4);
            fail("Would be past end.");
        }
        catch (IllegalArgumentException ilex)
        {

        }

        try
        {
            buf.bN(-1);
            TestCase.fail("Would be past end.");
        }
        catch (IllegalArgumentException ilex)
        {

        }

        isEquals(0, buf.bN(0).length);
        byte[] b = buf.bN(3);
        isEquals("Length", b.length, 3);
        isTrue("Wrong values", Arrays.equals(b, expected));
    }


    public void testRangeReadPastEnd()
        throws Exception
    {
        byte[] expected = new byte[]{1, 2, 3, 4, 5};

        KeyBoxByteBuffer buf = KeyBoxByteBuffer.wrap(expected);
        try
        {
            buf.rangeOf(3, 6);
            fail("Would be past end.");
        }
        catch (IllegalArgumentException ilex)
        {

        }

        try
        {
            buf.rangeOf(1, -3);
            fail("End is negative");
        }
        catch (IllegalArgumentException ilex)
        {

        }

        try
        {
            buf.rangeOf(4, 3);
            fail("End is less than start");
        }
        catch (IllegalArgumentException ilex)
        {

        }

        isEquals(0, buf.rangeOf(1, 1).length);
        byte[] b = buf.rangeOf(1, 3);
        isEquals("wrong length", 2, b.length);
        isTrue("Wrong values", Arrays.equals(b, new byte[]{2, 3}));
    }

    public void testConsumeReadPastEnd()
        throws Exception
    {
        KeyBoxByteBuffer buf = KeyBoxByteBuffer.wrap(new byte[4]);
        buf.consume(3);
        isEquals(-16, buf.size());
        try
        {
            buf.consume(2);
            TestCase.fail("consume past end of buffer");
        }
        catch (IllegalArgumentException ilex)
        {

        }
        buf.position(0);
    }

    public void testExceptions()
        throws IOException
    {
        testException("Could not convert ", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                KeyBoxByteBuffer.wrap(new Object());
            }
        });
        final KeyBoxByteBuffer buf = KeyBoxByteBuffer.wrap(new byte[4]);
        testException("invalid range ", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                buf.rangeOf(-1, 2);
            }
        });

        testException("range exceeds buffer remaining", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                buf.rangeOf(0, 24);
            }
        });

        testException("size exceeds buffer remaining", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                buf.consume(buf.remaining() + 1);
            }
        });

        testException("size less than 0", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                buf.bN(-1);
            }
        });

        testException("size exceeds buffer remaining", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                KeyBoxByteBuffer buf1 = KeyBoxByteBuffer.wrap(new byte[21]);
                buf1.consume(22);
            }
        });
    }

    public void testU32Unsigned()
        throws Exception
    {
        // u32() must read a full unsigned 32-bit value; bit 31 set must not sign-extend to a negative long.
        isTrue("0xFFFFFFFF", KeyBoxByteBuffer.wrap(new byte[]{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF}).u32() == 0xFFFFFFFFL);
        isTrue("0x80000000", KeyBoxByteBuffer.wrap(new byte[]{(byte)0x80, 0, 0, 0}).u32() == 0x80000000L);
        isTrue("0x7FFFFFFF", KeyBoxByteBuffer.wrap(new byte[]{(byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF}).u32() == 0x7FFFFFFFL);
        isTrue("0x00000100", KeyBoxByteBuffer.wrap(new byte[]{0, 0, 1, 0}).u32() == 0x100L);
    }

    @Override
    public String getName()
    {
        return "KeyBoxBuffer";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testConsumeReadPastEnd();
        testRangeReadPastEnd();
        testReadPastEnd();
        testExceptions();
        testU32Unsigned();
    }
}
