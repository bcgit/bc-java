package org.bouncycastle.tls.test;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import junit.framework.TestCase;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.Arrays;

/**
 * TlsUtils.readFully and readAllOrNothing take their byte count from the wire and used to size the
 * destination buffer from it before any of those bytes had arrived, so a handful of input bytes
 * could name a very large allocation pre-authentication. Both now read through
 * Streams.readLenBytesFully, which grows its buffer as bytes are delivered - deliberately not an
 * available() clamp, which would change what these public methods return for a caller passing a
 * socket or any other stream that under-reports.
 */
public class TlsUtilsReadFullyTest
    extends TestCase
{
    public void testReadFullyDoesNotAllocateFromDeclaredLength()
        throws IOException
    {
        try
        {
            // 2^31-1 exceeds the VM array limit, so a pre-allocating readFully raises an Error here
            TlsUtils.readFully(Integer.MAX_VALUE, new ByteArrayInputStream(new byte[8]));
            fail("hostile length accepted");
        }
        catch (EOFException e)
        {
            // expected: the stream runs out long before the declared length
        }
    }

    public void testReadOpaque24DoesNotAllocateFromDeclaredLength()
        throws IOException
    {
        try
        {
            // 0xFFFFFF is only 16MB, so this one passed before the fix too - wire-path assertion only
            TlsUtils.readOpaque24(new ByteArrayInputStream(new byte[]{(byte)0xFF, (byte)0xFF, (byte)0xFF}));
            fail("hostile opaque24 length accepted");
        }
        catch (EOFException e)
        {
            // expected
        }
    }

    public void testReadFullyStillReadsExactly()
        throws IOException
    {
        byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

        assertTrue(Arrays.areEqual(data, TlsUtils.readFully(8, new ByteArrayInputStream(data))));
        assertTrue(Arrays.areEqual(new byte[]{1, 2, 3},
            TlsUtils.readFully(3, new ByteArrayInputStream(data))));
        assertEquals(0, TlsUtils.readFully(0, new ByteArrayInputStream(data)).length);

        byte[] opaque = new byte[]{0x00, 0x00, 0x03, 0x0a, 0x0b, 0x0c};
        assertTrue(Arrays.areEqual(new byte[]{0x0a, 0x0b, 0x0c},
            TlsUtils.readOpaque24(new ByteArrayInputStream(opaque))));
    }

    public void testReadAllOrNothingContract()
        throws IOException
    {
        // empty gives null, complete gives the bytes, truncated is an EOFException
        assertNull(TlsUtils.readAllOrNothing(4, new ByteArrayInputStream(new byte[0])));

        byte[] data = new byte[]{9, 8, 7, 6};
        assertTrue(Arrays.areEqual(data, TlsUtils.readAllOrNothing(4, new ByteArrayInputStream(data))));

        try
        {
            TlsUtils.readAllOrNothing(4, new ByteArrayInputStream(new byte[]{9, 8}));
            fail("partial read accepted");
        }
        catch (EOFException e)
        {
            // expected
        }

        try
        {
            TlsUtils.readAllOrNothing(Integer.MAX_VALUE, new ByteArrayInputStream(new byte[8]));
            fail("hostile length accepted");
        }
        catch (EOFException e)
        {
            // expected
        }
    }

    public void testLyingAvailableIsNotTrusted()
        throws IOException
    {
        byte[] data = new byte[]{1, 2, 3, 4};

        // a stream over-reporting available() must not make the read truncate
        InputStream lying = new ByteArrayInputStream(data)
        {
            public int available()
            {
                return 1024 * 1024;
            }
        };

        assertTrue(Arrays.areEqual(data, TlsUtils.readFully(4, lying)));
    }
}
