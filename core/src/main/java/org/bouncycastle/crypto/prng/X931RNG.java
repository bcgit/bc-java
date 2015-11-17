package org.bouncycastle.crypto.prng;

import org.bouncycastle.crypto.BlockCipher;

public class X931RNG
{
    private static final long       BLOCK64_RESEED_MAX = 1L << (16 - 1);
    private static final long       BLOCK128_RESEED_MAX = 1L << (24 - 1);
    private static final int        BLOCK64_MAX_BITS_REQUEST = 1 << (13 - 1);
    private static final int        BLOCK128_MAX_BITS_REQUEST = 1 << (19 - 1);
    
    private final BlockCipher engine;
    private final EntropySource entropySource;

    private final byte[] DT;
    private final byte[] I;
    private final byte[] R;;

    private byte[] V;

    private long reseedCounter = 1;

    /**
     *
     * @param engine
     * @param entropySource
     */
    public X931RNG(BlockCipher engine, byte[] dateTimeVector, EntropySource entropySource)
    {
        this.engine = engine;
        this.entropySource = entropySource;

        this.DT = new byte[engine.getBlockSize()];

        System.arraycopy(dateTimeVector, 0, DT, 0, DT.length);

        this.I = new byte[engine.getBlockSize()];
        this.R = new byte[engine.getBlockSize()];
    }

    /**
     * Populate a passed in array with random data.
     *
     * @param output output array for generated bits.
     * @param predictionResistant true if a reseed should be forced, false otherwise.
     *
     * @return number of bits generated, -1 if a reseed required.
     */
    int generate(byte[] output, boolean predictionResistant)
    {
        if (R.length == 8) // 64 bit block size
        {
            if (reseedCounter > BLOCK64_RESEED_MAX)
            {
                return -1;
            }

            if (isTooLarge(output, BLOCK64_MAX_BITS_REQUEST / 8))
            {
                throw new IllegalArgumentException("Number of bits per request limited to " + BLOCK64_MAX_BITS_REQUEST);
            }
        }
        else
        {
            if (reseedCounter > BLOCK128_RESEED_MAX)
            {
                return -1;
            }

            if (isTooLarge(output, BLOCK128_MAX_BITS_REQUEST / 8))
            {
                throw new IllegalArgumentException("Number of bits per request limited to " + BLOCK128_MAX_BITS_REQUEST);
            }
        }
        
        if (predictionResistant || V == null)
        {
            V = entropySource.getEntropy();
            if (V.length != engine.getBlockSize())
            {
                throw new IllegalStateException("Insufficient entropy returned");
            }
        }

        int m = output.length / R.length;

        for (int i = 0; i < m; i++)
        {
            engine.processBlock(DT, 0, I, 0);
            process(R, I, V);
            process(V, R, I);

            System.arraycopy(R, 0, output, i * R.length, R.length);

            increment(DT);
        }

        int bytesToCopy = (output.length - m * R.length);

        if (bytesToCopy > 0)
        {
            engine.processBlock(DT, 0, I, 0);
            process(R, I, V);
            process(V, R, I);

            System.arraycopy(R, 0, output, m * R.length, bytesToCopy);

            increment(DT);
        }

        reseedCounter++;

        return output.length;
    }

    /**
     * Reseed the RNG.
     */
    void reseed()
    {
        V = entropySource.getEntropy();
        if (V.length != engine.getBlockSize())
        {
            throw new IllegalStateException("Insufficient entropy returned");
        }
        reseedCounter = 1;
    }

    EntropySource getEntropySource()
    {
        return entropySource;
    }

    private void process(byte[] res, byte[] a, byte[] b)
    {
        for (int i = 0; i != res.length; i++)
        {
            res[i] = (byte)(a[i] ^ b[i]);
        }

        engine.processBlock(res, 0, res, 0);
    }

    private void increment(byte[] val)
    {
        for (int i = val.length - 1; i >= 0; i--)
        {
            if (++val[i] != 0)
            {
                break;
            }
        }
    }
    
    private static boolean isTooLarge(byte[] bytes, int maxBytes)
    {
        return bytes != null && bytes.length > maxBytes;
    }
}
