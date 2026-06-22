package org.bouncycastle.mls.test;

import java.io.IOException;

import junit.framework.TestCase;

import org.bouncycastle.mls.codec.MLSInputStream;
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
}
