package org.bouncycastle.cert.ct;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Tiny big-endian, length-prefixed TLS-byte writer used by the CT decoders'
 * {@code getEncoded()} round-trip paths. Package-private; not part of the
 * public API.
 */
final class CTByteWriter
{
    private final ByteArrayOutputStream out;

    CTByteWriter(ByteArrayOutputStream out)
    {
        this.out = out;
    }

    void writeU8(int v)
        throws IOException
    {
        if ((v & ~0xFF) != 0)
        {
            throw new IllegalArgumentException("value " + v + " does not fit in a uint8");
        }
        out.write(v);
    }

    void writeU16(int v)
        throws IOException
    {
        if ((v & ~0xFFFF) != 0)
        {
            throw new IllegalArgumentException("value " + v + " does not fit in a uint16");
        }
        out.write((v >>> 8) & 0xFF);
        out.write(v & 0xFF);
    }

    void writeU64(long v)
        throws IOException
    {
        for (int i = 7; i >= 0; i--)
        {
            out.write((int)((v >>> (i * 8)) & 0xFFL));
        }
    }

    void writeBytes(byte[] bytes)
        throws IOException
    {
        out.write(bytes);
    }

    /** Write a 2-byte length prefix followed by the supplied bytes. */
    void writeOpaqueU16(byte[] bytes)
        throws IOException
    {
        writeU16(bytes.length);
        out.write(bytes);
    }

    /** Write a 1-byte length prefix followed by the supplied bytes. */
    void writeOpaqueU8(byte[] bytes)
        throws IOException
    {
        writeU8(bytes.length);
        out.write(bytes);
    }
}
