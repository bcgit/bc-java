package org.bouncycastle.bcpg;

public abstract class CRC24
{
    private static boolean USE_FAST_IMPLEMENTATION = false;

    private static final int CRC24_INIT = 0x0b704ce;
    private static final int CRC24_POLY = 0x1864cfb;

    public abstract void update(int b);

    public abstract int getValue();

    public abstract void reset();

    /**
     * Return an instance of the {@link CRC24} class.
     * If {@link #USE_FAST_IMPLEMENTATION} is set (see {@link #setUseFastImplementation(boolean)}), then a fast
     * implementation (see {@link #fastCRC24()}) is returned, otherwise the method returns a conventional,
     * but slower implementation (see {@link #iterativeCRC24()}).
     *
     * @return CRC-24 instance
     */
    public static CRC24 getInstance() {
        if (USE_FAST_IMPLEMENTATION) {
            return fastCRC24();
        } else {
            return iterativeCRC24();
        }
    }

    /**
     * Specify, whether to use the fast CRC-24 implementation.
     * If set to true, {@link #getInstance()} will return the fast implementation, otherwise it will return the
     * slow, but conventional iterative implementation.
     *
     * @param useFastImplementation use fast implementation
     */
    public static void setUseFastImplementation(boolean useFastImplementation) {
        USE_FAST_IMPLEMENTATION = useFastImplementation;
    }

    /**
     * Default, iterative CRC-24 implementation as described in RFC4880.
     * This implementation mimics the use of a feedback shift register in software.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-6.1">
     *     RFC4880 §6.1. An Implementation of the CRC-24 in "C"</a>
     *
     * @return default CRC-24 implementation
     */
    public static CRC24 iterativeCRC24() {

        return new CRC24() {

            private int crc = CRC24_INIT;

            @Override
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

            @Override
            public int getValue()
            {
                return crc;
            }

            @Override
            public void reset()
            {
                crc = CRC24_INIT;
            }
        };
    }

    private static int[] TABLE = null;

    /**
     * Fast CRC-24 implementation using a lookup table to handle multiple bits at a time.
     *
     * Compare: Sarwate, Dilip V. "Computation of cyclic redundancy checks via table look-up."
     * @return fast implementation
     */
    public static CRC24 fastCRC24() {
        return new CRC24() {
            private int crc = CRC24_INIT;

            @Override
            public void update(int b) {
                // b^(crc>>16) mod 256
                int index = (b ^ (crc >> 16)) & ~-256;
                crc = (crc << 8) ^ getTable()[index];
            }

            @Override
            public int getValue() {
                return crc & 0xFFFFFF;
            }

            @Override
            public void reset() {
                crc = CRC24_INIT;
            }
        };
    }

    /**
     * Lazily init and return the lookup table.
     *
     * @return lookup table
     */
    private static synchronized int[] getTable() {
        if (TABLE != null) {
            return TABLE;
        }

        TABLE = new int[256];
        int crc = 0x800000;
        int i = 1;
        while (i != 256) {
            if ((crc & 0x800000) > 0) {
                crc = (crc << 1) ^ CRC24_POLY;
            } else {
                crc <<= 1;
            }

            for (int j = 0; j < i; j++) {
                TABLE[i + j] = crc ^ TABLE[j];
            }
            i <<= 1;
        }
        return TABLE;
    }

}
