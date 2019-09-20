package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Pack;

/**
 * Implementation of Daniel J. Bernstein's ChaCha stream cipher.
 */
public class ChaCha7539Engine extends Salsa20Engine
{
    /**
     * Creates a 20 rounds ChaCha engine.
     */
    public ChaCha7539Engine()
    {
        super();
    }

    public String getAlgorithmName()
    {
        return "ChaCha7539";
    }

    protected int getNonceSize()
    {
        return 12;
    }

    protected void advanceCounter(long diff)
    {
        int hi = (int)(diff >>> 32);
        int lo = (int)diff;

        if (hi > 0)
        {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }

        int oldState = engineState[12];

        engineState[12] += lo;

        if (oldState != 0 && engineState[12] < oldState)
        {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }
    }

    protected void advanceCounter()
    {
        if (++engineState[12] == 0)
        {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }
    }

    protected void retreatCounter(long diff)
    {
        int hi = (int)(diff >>> 32);
        int lo = (int)diff;

        if (hi != 0)
        {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }

        if ((engineState[12] & 0xffffffffL) >= (lo & 0xffffffffL))
        {
            engineState[12] -= lo;
        }
        else
        {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
    }

    protected void retreatCounter()
    {
        if (engineState[12] == 0)
        {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }

        --engineState[12];
    }

    protected long getCounter()
    {
        return engineState[12] & 0xffffffffL;
    }

    protected void resetCounter()
    {
        engineState[12] = 0;
    }

    protected void setKey(byte[] keyBytes, byte[] ivBytes)
    {
        if (keyBytes != null)
        {
            if (keyBytes.length != 32)
            {
                throw new IllegalArgumentException(getAlgorithmName() + " requires 256 bit key");
            }

            packTauOrSigma(keyBytes.length, engineState, 0);

            // Key
            Pack.littleEndianToInt(keyBytes, 0, engineState, 4, 8);
        }

        // IV
        Pack.littleEndianToInt(ivBytes, 0, engineState, 13, 3);
    }

    protected void generateKeyStream(byte[] output)
    {
        ChaChaEngine.chachaCore(rounds, engineState, x);
        Pack.intToLittleEndian(x, output, 0);
    }
}
