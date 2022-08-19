package org.bouncycastle.bcpg;

public class FastCRC24
    extends CRC24
{
    private static final int[] TABLE = getTable();

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
        // b^(crc>>16) mod 256
        int index = (b ^ (crc >> 16)) & ~-256;
        crc = (crc << 8) ^ TABLE[index];
    }

    /**
     * Lazily init and return the lookup table.
     *
     * @return lookup table
     */
    private static int[] getTable()
    {
        int[] TABLE = new int[256];
        int crc = 0x800000;
        int i = 1;
        while (i != 256)
        {
            if ((crc & 0x800000) > 0)
            {
                crc = (crc << 1) ^ CRC24_POLY;
            }
            else
            {
                crc <<= 1;
            }

            for (int j = 0; j < i; j++)
            {
                TABLE[i + j] = crc ^ TABLE[j];
            }
            i <<= 1;
        }
        return TABLE;
    }
}
