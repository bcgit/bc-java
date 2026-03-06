package org.bouncycastle.cert.plants;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

class Utils
{
    static void writeUint64(ByteArrayOutputStream baos, long v)
    {
        baos.write((byte)(v >>> 56));
        baos.write((byte)(v >>> 48));
        baos.write((byte)(v >>> 40));
        baos.write((byte)(v >>> 32));
        baos.write((byte)(v >>> 24));
        baos.write((byte)(v >>> 16));
        baos.write((byte)(v >>> 8));
        baos.write((byte)v);
    }

    // ----- I/O helpers -----
    static long readUint64(ByteArrayInputStream in) throws IOException
    {
        byte[] buf = new byte[8];
        if (in.read(buf) != 8)
        {
            throw new IOException("Truncated uint64");
        }
        return ((buf[0] & 0xFFL) << 56) |
            ((buf[1] & 0xFFL) << 48) |
            ((buf[2] & 0xFFL) << 40) |
            ((buf[3] & 0xFFL) << 32) |
            ((buf[4] & 0xFFL) << 24) |
            ((buf[5] & 0xFFL) << 16) |
            ((buf[6] & 0xFFL) << 8)  |
            (buf[7] & 0xFFL);
    }

    static int readUint16(ByteArrayInputStream in) throws IOException
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

    static long readUint64(byte[] data, int off)
    {
        return ((data[off] & 0xFFL) << 56) |
            ((data[off + 1] & 0xFFL) << 48) |
            ((data[off + 2] & 0xFFL) << 40) |
            ((data[off + 3] & 0xFFL) << 32) |
            ((data[off + 4] & 0xFFL) << 24) |
            ((data[off + 5] & 0xFFL) << 16) |
            ((data[off + 6] & 0xFFL) << 8) |
            (data[off + 7] & 0xFFL);
    }
}
