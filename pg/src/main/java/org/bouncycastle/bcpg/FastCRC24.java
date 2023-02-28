package org.bouncycastle.bcpg;

public class FastCRC24
    extends CRC24
{
    private static final int[] TABLE0, TABLE8, TABLE16;

    static
    {
        int[] table0 = new int[256];
        int[] table8 = new int[256];
        int[] table16 = new int[256];

        int crc = 0x800000;
        for (int i = 1; i < 256; i <<= 1)
        {
            int carry = ((crc << 8) >> 31) & CRC24_POLY;
            crc = (crc << 1) ^ carry;

            for (int j = 0; j < i; ++j)
            {
                table0[i + j] = crc ^ table0[j];
            }
        }

        for (int i = 1; i < 256; ++i)
        {
            int crc0 = table0[i];
            int crc8 = ((crc0 & 0xFFFF) << 8) ^ table0[(crc0 >> 16) & 255];
            int crc16 = ((crc8 & 0xFFFF) << 8) ^ table0[(crc8 >> 16) & 255];

            table8[i] = crc8;
            table16[i] = crc16;
        }

        TABLE0 = table0;
        TABLE8 = table8;
        TABLE16 = table16;
    }

    /**
     * Fast CRC-24 implementation using a lookup table to handle multiple bits at a time.
     * <p>
     * Compare: Sarwate, Dilip V. "Computation of cyclic redundancy checks via table look-up."
     */
    public FastCRC24()
    {
    }

    public void update(int b)
    {
        int index = (b ^ (crc >> 16)) & 255;
        crc = (crc << 8) ^ TABLE0[index];
    }

    public void update3(byte[] buf, int off)
    {
        crc = TABLE16[(buf[off + 0] ^ (crc >> 16)) & 255]
            ^ TABLE8[(buf[off + 1] ^ (crc >> 8)) & 255]
            ^ TABLE0[(buf[off + 2] ^ crc) & 255];
    }
}
