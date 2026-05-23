package org.bouncycastle.cert.plants;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Package-private TLS-wire encoding helpers for the fixed-width unsigned
 * integers used by the MTCProof / LandmarkSequence / CosignedMessage formats
 * defined in draft-ietf-plants-merkle-tree-certs.
 */
class MTCEncoding
{
    static int readUint16(ByteArrayInputStream in)
        throws IOException
    {
        int b1 = in.read();
        int b2 = in.read();
        if ((b1 | b2) < 0)
        {
            throw new IOException("Truncated uint16");
        }
        return (b1 << 8) | b2;
    }

    static void writeUint16(ByteArrayOutputStream baos, int v)
    {
        baos.write((byte)(v >>> 8));
        baos.write((byte)v);
    }

    static void writeUint48(ByteArrayOutputStream baos, long v)
    {
        if (v < 0 || v > 0xFFFFFFFFFFFFL)
        {
            throw new IllegalArgumentException("uint48 out of range: " + v);
        }
        baos.write((byte)(v >>> 40));
        baos.write((byte)(v >>> 32));
        baos.write((byte)(v >>> 24));
        baos.write((byte)(v >>> 16));
        baos.write((byte)(v >>> 8));
        baos.write((byte)v);
    }

    static long readUint48(ByteArrayInputStream in)
        throws IOException
    {
        byte[] buf = new byte[6];
        if (in.read(buf) != 6)
        {
            throw new IOException("Truncated uint48");
        }
        return ((buf[0] & 0xFFL) << 40) |
            ((buf[1] & 0xFFL) << 32) |
            ((buf[2] & 0xFFL) << 24) |
            ((buf[3] & 0xFFL) << 16) |
            ((buf[4] & 0xFFL) << 8) |
            (buf[5] & 0xFFL);
    }
}
