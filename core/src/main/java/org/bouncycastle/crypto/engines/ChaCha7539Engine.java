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

    /*
     * The 32-bit block counter allows 2^32 blocks of 64 bytes (RFC 8439, section 2.4). The block for counter
     * 0xFFFFFFFF is the last one, and the stream may end exactly after it.
     */
    private static final long MAX_COUNTER = 1L << 32;
    private static final long MAX_POSITION = MAX_COUNTER * 64;

    /*
     * Set when the counter has moved past 0xFFFFFFFF, i.e. the whole keystream has been used (or skipped). The
     * counter word itself has wrapped to 0 then, so this flag, not engineState[12], says where the stream is: no
     * further keystream may be produced until the counter moves back (skip/seekTo) or is reset.
     */
    private boolean counterExhausted;

    public byte returnByte(byte in)
    {
        if (getPosition() >= MAX_POSITION)
        {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }

        return super.returnByte(in);
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
    {
        if (len > MAX_POSITION - getPosition())
        {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }

        return super.processBytes(in, inOff, len, out, outOff);
    }

    public long skip(long numberOfBytes)
    {
        if (numberOfBytes > MAX_POSITION - getPosition())
        {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }

        return super.skip(numberOfBytes);
    }

    protected void advanceCounter(long diff)
    {
        long counter = getCounter();

        if (diff < 0 || diff > MAX_COUNTER - counter)
        {
            throw new IllegalStateException("attempt to increase counter past 2^32.");
        }

        setCounter(counter + diff);
    }

    protected void advanceCounter()
    {
        advanceCounter(1);
    }

    protected void retreatCounter(long diff)
    {
        long counter = getCounter();

        if (diff < 0 || diff > counter)
        {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }

        setCounter(counter - diff);
    }

    protected void retreatCounter()
    {
        retreatCounter(1);
    }

    protected long getCounter()
    {
        return counterExhausted ? MAX_COUNTER : engineState[12] & 0xffffffffL;
    }

    protected void resetCounter()
    {
        setCounter(0);
    }

    private void setCounter(long counter)
    {
        engineState[12] = (int)counter;
        counterExhausted = (counter == MAX_COUNTER);
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
