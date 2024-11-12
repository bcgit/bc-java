package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Pack;

abstract class AsconDefaultDigest
    implements ExtendedDigest
{
    protected long x0;
    protected long x1;
    protected long x2;
    protected long x3;
    protected long x4;
    protected final int CRYPTO_BYTES = 32;
    protected final int ASCON_HASH_RATE = 8;
    protected int ASCON_PB_ROUNDS = 12;

    protected final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    protected long ROR(long x, int n)
    {
        return x >>> n | x << (64 - n);
    }

    protected void ROUND(long C)
    {
        long t0 = x0 ^ x1 ^ x2 ^ x3 ^ C ^ (x1 & (x0 ^ x2 ^ x4 ^ C));
        long t1 = x0 ^ x2 ^ x3 ^ x4 ^ C ^ ((x1 ^ x2 ^ C) & (x1 ^ x3));
        long t2 = x1 ^ x2 ^ x4 ^ C ^ (x3 & x4);
        long t3 = x0 ^ x1 ^ x2 ^ C ^ ((~x0) & (x3 ^ x4));
        long t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
        x0 = t0 ^ ROR(t0, 19) ^ ROR(t0, 28);
        x1 = t1 ^ ROR(t1, 39) ^ ROR(t1, 61);
        x2 = ~(t2 ^ ROR(t2, 1) ^ ROR(t2, 6));
        x3 = t3 ^ ROR(t3, 10) ^ ROR(t3, 17);
        x4 = t4 ^ ROR(t4, 7) ^ ROR(t4, 41);
    }

    protected void P(int nr)
    {
        if (nr == 12)
        {
            ROUND(0xf0L);
            ROUND(0xe1L);
            ROUND(0xd2L);
            ROUND(0xc3L);
        }
        if (nr >= 8)
        {
            ROUND(0xb4L);
            ROUND(0xa5L);
        }
        ROUND(0x96L);
        ROUND(0x87L);
        ROUND(0x78L);
        ROUND(0x69L);
        ROUND(0x5aL);
        ROUND(0x4bL);
    }

    protected long PAD(int i)
    {
        return 0x01L << (i << 3);
    }

    protected long LOADBYTES(final byte[] bytes, int inOff, int n)
    {
        return Pack.littleEndianToLong(bytes, inOff, n);
    }

    protected void STOREBYTES(long w, byte[] bytes, int inOff, int n)
    {
        Pack.longToLittleEndian(w, bytes, inOff, n);
    }

    @Override
    public int getDigestSize()
    {
        return CRYPTO_BYTES;
    }

    @Override
    public int getByteLength()
    {
        return 8;
    }

    @Override
    public void update(byte in)
    {
        buffer.write(in);
    }

    @Override
    public void update(byte[] input, int inOff, int len)
    {
        if ((inOff + len) > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        buffer.write(input, inOff, len);
    }

    protected void absorb(byte[] input, int len)
    {
        int inOff = 0;
        /* absorb full plaintext blocks */
        while (len >= ASCON_HASH_RATE)
        {
            x0 ^= LOADBYTES(input, inOff, 8);
            P(ASCON_PB_ROUNDS);
            inOff += ASCON_HASH_RATE;
            len -= ASCON_HASH_RATE;
        }
        /* absorb final plaintext block */
        x0 ^= LOADBYTES(input, inOff, len);
        x0 ^= PAD(len);
        P(12);
    }

    protected void squeeze(byte[] output, int outOff, int len)
    {
        /* squeeze full output blocks */
        while (len > ASCON_HASH_RATE)
        {
            STOREBYTES(x0, output, outOff, 8);
            P(ASCON_PB_ROUNDS);
            outOff += ASCON_HASH_RATE;
            len -= ASCON_HASH_RATE;
        }
        /* squeeze final output block */
        STOREBYTES(x0, output, outOff, len);
        reset();
    }

    protected int hash(byte[] output, int outOff, int outLen)
    {
        if (CRYPTO_BYTES + outOff > output.length)
        {
            throw new OutputLengthException("output buffer is too short");
        }
        absorb(buffer.toByteArray(), buffer.size());
        /* squeeze full output blocks */
        squeeze(output, outOff, outLen);
        return outLen;
    }
}
