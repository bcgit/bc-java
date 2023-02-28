package org.bouncycastle.bcpg;

public class CRC24
{
    protected static final int CRC24_INIT = 0x0b704ce;
    protected static final int CRC24_POLY = 0x1864cfb;

    protected int crc = CRC24_INIT;

    /**
     * Default, iterative CRC-24 implementation as described in RFC4880.
     * This implementation mimics the use of a feedback shift register in software.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-6.1">
     * RFC4880 §6.1. An Implementation of the CRC-24 in "C"</a>
     */
    public CRC24()
    {
    }

    public void update(int b)
    {
        crc ^= b << 16;
        for (int i = 0; i < 8; i++)
        {
            int carry = ((crc << 8) >> 31) & CRC24_POLY;
            crc = (crc << 1) ^ carry;
        }
    }

    public void update3(byte[] buf, int off)
    {
        update(buf[off + 0] & 0xFF);
        update(buf[off + 1] & 0xFF);
        update(buf[off + 2] & 0xFF);
    }

    public int getValue()
    {
        return crc & 0xFFFFFF;
    }

    public void reset()
    {
        crc = CRC24_INIT;
    }
}
