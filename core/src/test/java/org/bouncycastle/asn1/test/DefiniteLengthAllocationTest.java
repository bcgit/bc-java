package org.bouncycastle.asn1.test;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression coverage for the definite-length materialization allocation guard in
 * {@code DefiniteLengthInputStream.toByteArray()}. When {@code ASN1InputStream} wraps a raw
 * (non-array, non-file) stream, the per-object limit falls back to {@code Runtime.maxMemory}
 * ({@code StreamUtil.findLimit}), so allocating the full declared length up front let a short
 * crafted header - an OCTET STRING declaring a near-heap length with no body - drive an
 * OutOfMemoryError before any data was read (CWE-789). The buffer is now grown as bytes actually
 * arrive: a short input allocates only a bounded working buffer, a well-formed object still
 * materializes correctly, and a truncated object still fails with the established
 * "DEF length ... object truncated by ..." EOFException.
 */
public class DefiniteLengthAllocationTest
    extends SimpleTest
{
    public String getName()
    {
        return "DefiniteLengthAllocation";
    }

    public void performTest()
        throws Exception
    {
        testDeclaredLengthNotAllocatedUpFront();
        testTruncatedObjectReportsExpectedMessage();
    }

    /**
     * A large declared length must not be requested (and therefore allocated) in a single up-front
     * read: the eager {@code new byte[length]} asked the stream for the whole declared length at
     * once, whereas the guard reads into a bounded, incrementally grown buffer.
     */
    private void testDeclaredLengthNotAllocatedUpFront()
        throws IOException
    {
        int declaredLength = 1 << 20;   // 1 MiB - comfortably past the bounded working buffer

        // OCTET STRING (tag 0x04), long-form length 0x100000, followed by a full body.
        byte[] input = new byte[5 + declaredLength];
        input[0] = (byte)0x04;
        input[1] = (byte)0x83;          // long form, 3 length octets
        input[2] = (byte)0x10;
        input[3] = (byte)0x00;
        input[4] = (byte)0x00;

        RecordingStream in = new RecordingStream(input);
        ASN1OctetString octets = (ASN1OctetString)new ASN1InputStream(in).readObject();

        isTrue("octet string did not materialize to the declared length",
            octets.getOctets().length == declaredLength);
        isTrue("first bulk read requested the full declared length (" + in.firstBulkReadLength + ")",
            in.firstBulkReadLength >= 0 && in.firstBulkReadLength < declaredLength);
    }

    /**
     * A definite-length object whose stream ends early still fails with the exact truncation
     * message the eager read produced (the message text is asserted elsewhere in the suite).
     */
    private void testTruncatedObjectReportsExpectedMessage()
    {
        int declaredLength = 1 << 20;
        int bodySupplied = 10;

        byte[] input = new byte[5 + bodySupplied];
        input[0] = (byte)0x04;
        input[1] = (byte)0x83;
        input[2] = (byte)0x10;
        input[3] = (byte)0x00;
        input[4] = (byte)0x00;

        try
        {
            new ASN1InputStream(new RecordingStream(input)).readObject();
            fail("no exception on truncated definite-length object");
        }
        catch (EOFException e)
        {
            String expected = "DEF length " + declaredLength + " object truncated by " + (declaredLength - bodySupplied);
            isTrue("unexpected truncation message: " + e.getMessage(), expected.equals(e.getMessage()));
        }
        catch (IOException e)
        {
            fail("unexpected exception: " + e);
        }
    }

    /**
     * A generic InputStream (so StreamUtil.findLimit takes the Runtime.maxMemory fallback) that
     * records the size of the first bulk read(byte[], int, int) request.
     */
    private static final class RecordingStream
        extends InputStream
    {
        private final byte[] data;
        private int pos = 0;
        int firstBulkReadLength = -1;

        RecordingStream(byte[] data)
        {
            this.data = data;
        }

        public int read()
        {
            return pos < data.length ? (data[pos++] & 0xFF) : -1;
        }

        public int read(byte[] buf, int off, int len)
        {
            if (firstBulkReadLength < 0)
            {
                firstBulkReadLength = len;
            }
            if (pos >= data.length)
            {
                return -1;
            }
            int n = Math.min(len, data.length - pos);
            System.arraycopy(data, pos, buf, off, n);
            pos += n;
            return n;
        }
    }

    public static void main(String[] args)
    {
        runTest(new DefiniteLengthAllocationTest());
    }
}
