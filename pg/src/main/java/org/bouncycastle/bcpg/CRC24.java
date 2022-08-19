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

    public void update(
        int b)
    {
        crc ^= b << 16;
        for (int i = 0; i < 8; i++)
        {
            crc <<= 1;
            if ((crc & 0x1000000) != 0)
            {
                crc ^= CRC24_POLY;
            }
        }
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
