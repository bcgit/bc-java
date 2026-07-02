package org.bouncycastle.mls.test;

import java.io.IOException;

import junit.framework.TestCase;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSMessage;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class MLSInputStreamTest
    extends TestCase
{
    // CVD ANT-2026-2FXSJ3RD: readOpaque() decodes an attacker-controlled Varint length (up to
    // 0x3FFFFFFF, ~1 GiB) and previously passed it straight to new byte[size] before checking that
    // the input actually held that many bytes. A tiny unauthenticated wire message could therefore
    // force a ~1 GiB allocation and exhaust the heap. The length must now be bounded by the bytes
    // actually remaining before any buffer is allocated.
    public void testOversizedOpaqueLengthRejected()
        throws Exception
    {
        // 4-byte Varint 0xBFFFFFFF decodes to length 0x3FFFFFFF, but no opaque bytes follow.
        MLSInputStream in = new MLSInputStream(Hex.decode("bfffffff"));
        try
        {
            in.readOpaque();
            fail("opaque length exceeding the available bytes was accepted");
        }
        catch (IOException e)
        {
            // expected: rejected against the remaining-byte count before allocating
        }
    }

    public void testValidOpaqueRoundTrips()
        throws Exception
    {
        // 1-byte Varint length 3, followed by the 3 opaque bytes
        MLSInputStream in = new MLSInputStream(Hex.decode("03aabbcc"));
        assertTrue(Arrays.areEqual(Hex.decode("aabbcc"), in.readOpaque()));
    }

    // readArray(non-byte elemClass) reads an attacker-controlled 4-byte element count and, before the
    // guard was added, passed it straight to Array.newInstance(elemClass, length). A count with the top
    // bit set decodes to a negative int, so Array.newInstance threw an uncaught NegativeArraySizeException
    // rather than a clean IOException like every other oversize read in the class.
    public void testNegativeArrayLengthRejected()
        throws Exception
    {
        // 4-byte element count 0x80000000 decodes to a negative length.
        MLSInputStream in = new MLSInputStream(Hex.decode("80000000"));
        try
        {
            in.readArray(Short.class);
            fail("negative array element count was accepted");
        }
        catch (IOException e)
        {
            // expected: rejected against the remaining-byte count before allocating
        }
    }

    // A non-byte array declaring far more elements than the bytes remaining previously forced an
    // up-front Array.newInstance allocation of that size (heap-exhaustion DoS) before the per-element
    // reads could fail. The element count must now be bounded by the bytes actually remaining first.
    public void testOversizedArrayLengthRejected()
        throws Exception
    {
        // 4-byte element count 0x40000000 (~1 billion), but no element bytes follow.
        MLSInputStream in = new MLSInputStream(Hex.decode("40000000"));
        try
        {
            in.readArray(Short.class);
            fail("array element count exceeding the available bytes was accepted");
        }
        catch (IOException e)
        {
            // expected: rejected against the remaining-byte count before allocating
        }
    }

    public void testValidArrayRoundTrips()
        throws Exception
    {
        // 4-byte element count 2, followed by two 2-byte shorts.
        MLSInputStream in = new MLSInputStream(Hex.decode("0000000211223344"));
        Object out = in.readArray(Short.class);
        assertTrue(out instanceof Short[]);
        Short[] shorts = (Short[])out;
        assertEquals(2, shorts.length);
        assertEquals((short)0x1122, shorts[0].shortValue());
        assertEquals((short)0x3344, shorts[1].shortValue());
    }

    // MLSMessage decode reads the outermost attacker-controlled ProtocolVersion / WireFormat as a
    // short index straight into enum.values()[idx]. An out-of-range index used to surface as a raw
    // ArrayIndexOutOfBoundsException opaquely re-wrapped to IOException("InvocationTargetException:
    // Index N out of bounds for length M"); the decode now rejects it with a descriptive message,
    // mirroring the Varint "Invalid varint header" / readBoolean "Invalid boolean value" guards in
    // the same codec package.
    public void testOutOfRangeProtocolVersionRejected()
        throws Exception
    {
        // ProtocolVersion has 2 constants (0,1); a leading short of 99 is out of range.
        byte[] data = Hex.decode("0063");
        try
        {
            MLSInputStream.decode(data, MLSMessage.class);
            fail("out-of-range ProtocolVersion index was accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage().indexOf("invalid ProtocolVersion") >= 0);
        }
    }

    public void testOutOfRangeWireFormatRejected()
        throws Exception
    {
        // version=1 (valid), then a WireFormat short of 99 (WireFormat has 6 constants, 0..5).
        byte[] data = Hex.decode("00010063");
        try
        {
            MLSInputStream.decode(data, MLSMessage.class);
            fail("out-of-range WireFormat index was accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage().indexOf("invalid WireFormat") >= 0);
        }
    }
}
