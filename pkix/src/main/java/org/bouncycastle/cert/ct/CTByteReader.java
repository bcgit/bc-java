package org.bouncycastle.cert.ct;

import org.bouncycastle.util.Arrays;

/**
 * Tiny big-endian, length-prefixed TLS-byte parser used by the CT decoders.
 * Package-private; not part of the public API.
 */
final class CTByteReader
{
    private final byte[] buffer;
    private int pos;
    private final int end;

    CTByteReader(byte[] buffer)
    {
        this(buffer, 0, buffer.length);
    }

    CTByteReader(byte[] buffer, int offset, int length)
    {
        this.buffer = buffer;
        this.pos = offset;
        this.end = offset + length;
    }

    int remaining()
    {
        return end - pos;
    }

    int readU8()
    {
        ensure(1);
        return buffer[pos++] & 0xFF;
    }

    int readU16()
    {
        ensure(2);
        int v = ((buffer[pos] & 0xFF) << 8) | (buffer[pos + 1] & 0xFF);
        pos += 2;
        return v;
    }

    long readU64()
    {
        ensure(8);
        long v = 0L;
        for (int i = 0; i < 8; i++)
        {
            v = (v << 8) | (buffer[pos + i] & 0xFFL);
        }
        pos += 8;
        return v;
    }

    byte[] readBytes(int n)
    {
        ensure(n);
        byte[] out = Arrays.copyOfRange(buffer, pos, pos + n);
        pos += n;
        return out;
    }

    /** Read a 2-byte length prefix followed by that many bytes. */
    byte[] readOpaqueU16()
    {
        int len = readU16();
        return readBytes(len);
    }

    /** Read a 1-byte length prefix followed by that many bytes. */
    byte[] readOpaqueU8()
    {
        int len = readU8();
        return readBytes(len);
    }

    /** Slice the next n bytes into an independent reader and advance past them. */
    CTByteReader subReader(int n)
    {
        ensure(n);
        CTByteReader sub = new CTByteReader(buffer, pos, n);
        pos += n;
        return sub;
    }

    private void ensure(int n)
    {
        if (n < 0 || pos + n > end)
        {
            throw new IllegalArgumentException("truncated CT structure: requested " + n
                + " bytes, only " + remaining() + " remain");
        }
    }
}
