package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.Pack;

/**
 * Implementation of SipHash as specified in "SipHash: a fast short-input PRF", by Jean-Philippe
 * Aumasson and Daniel J. Bernstein (https://131002.net/siphash/siphash.pdf).
 * <p/>
 * "SipHash is a family of PRFs SipHash-c-d where the integer parameters c and d are the number of
 * compression rounds and the number of finalization rounds. A compression round is identical to a
 * finalization round and this round function is called SipRound. Given a 128-bit key k and a
 * (possibly empty) byte string m, SipHash-c-d returns a 64-bit value..."
 */
public class SipHash
    implements Mac
{
    protected final int c, d;

    protected long k0, k1;
    protected long v0, v1, v2, v3, v4;

    protected long m = 0;
    protected int wordPos = 0;
    protected int wordCount = 0;

    /**
     * SipHash-2-4
     */
    public SipHash()
    {
        // use of 'this' confuses the flow analyser on earlier JDKs.
        this.c = 2;
        this.d = 4;
    }

    /**
     * SipHash-c-d
     *
     * @param c the number of compression rounds
     * @param d the number of finalization rounds
     */
    public SipHash(int c, int d)
    {
        this.c = c;
        this.d = d;
    }

    public String getAlgorithmName()
    {
        return "SipHash-" + c + "-" + d;
    }

    public int getMacSize()
    {
        return 8;
    }

    public void init(CipherParameters params)
        throws IllegalArgumentException
    {
        if (!(params instanceof KeyParameter))
        {
            throw new IllegalArgumentException("'params' must be an instance of KeyParameter");
        }
        KeyParameter keyParameter = (KeyParameter)params;
        byte[] key = keyParameter.getKey();
        if (key.length != 16)
        {
            throw new IllegalArgumentException("'params' must be a 128-bit key");
        }

        this.k0 = Pack.littleEndianToLong(key, 0);
        this.k1 = Pack.littleEndianToLong(key, 8);

        reset();
    }

    public void update(byte input)
        throws IllegalStateException
    {
        m >>>= 8;
        m |= (input & 0xffL) << 56;

        if (++wordPos == 8)
        {
            processMessageWord();
            wordPos = 0;
        }
    }

    public void update(byte[] input, int offset, int length)
        throws DataLengthException,
        IllegalStateException
    {
        int i = 0, fullWords = length & ~7;
        if (wordPos == 0)
        {
            for (; i < fullWords; i += 8)
            {
                m = Pack.littleEndianToLong(input, offset + i);
                processMessageWord();
            }
            for (; i < length; ++i)
            {
                m >>>= 8;
                m |= (input[offset + i] & 0xffL) << 56;
            }
            wordPos = length - fullWords;
        }
        else
        {
            int bits = wordPos << 3;
            for (; i < fullWords; i += 8)
            {
                long n = Pack.littleEndianToLong(input, offset + i);
                m >>>= 64 - bits;
                m |= n << bits;
                processMessageWord();
                m = n;
            }
            for (; i < length; ++i)
            {
                m >>>= 8;
                m |= (input[offset + i] & 0xffL) << 56;

                if (++wordPos == 8)
                {
                    processMessageWord();
                    wordPos = 0;
                }
            }
        }
    }

    public long doFinal()
        throws DataLengthException, IllegalStateException
    {
        m >>>= ((8 - wordPos) << 3);
        m |= (((wordCount << 3) + wordPos) & 0xffL) << 56;

        processMessageWord();

        v2 ^= 0xffL;

        applySipRounds(d);

        long result = v0 ^ v1 ^ v2 ^ v3;

        reset();

        return result;
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        long result = doFinal();
        Pack.longToLittleEndian(result, out, outOff);
        return 8;
    }

    public void reset()
    {
        v0 = k0 ^ 0x736f6d6570736575L;
        v1 = k1 ^ 0x646f72616e646f6dL;
        v2 = k0 ^ 0x6c7967656e657261L;
        v3 = k1 ^ 0x7465646279746573L;

        m = 0;
        wordPos = 0;
        wordCount = 0;
    }

    protected void processMessageWord()
    {
        ++wordCount;
        v3 ^= m;
        applySipRounds(c);
        v0 ^= m;
    }

    protected void applySipRounds(int n)
    {
        for (int r = 0; r < n; ++r)
        {
            v0 += v1;
            v2 += v3;
            v1 = rotateLeft(v1, 13);
            v3 = rotateLeft(v3, 16);
            v1 ^= v0;
            v3 ^= v2;
            v0 = rotateLeft(v0, 32);
            v2 += v1;
            v0 += v3;
            v1 = rotateLeft(v1, 17);
            v3 = rotateLeft(v3, 21);
            v1 ^= v2;
            v3 ^= v0;
            v2 = rotateLeft(v2, 32);
        }
    }

    protected static long rotateLeft(long x, int n)
    {
        return (x << n) | (x >>> (64 - n));
    }
}
