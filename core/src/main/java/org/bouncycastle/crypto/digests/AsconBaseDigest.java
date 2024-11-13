package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Pack;

abstract class AsconBaseDigest
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

    protected long ror(long x, int n)
    {
        return x >>> n | x << (64 - n);
    }

    protected void round(long C)
    {
        long t0 = x0 ^ x1 ^ x2 ^ x3 ^ C ^ (x1 & (x0 ^ x2 ^ x4 ^ C));
        long t1 = x0 ^ x2 ^ x3 ^ x4 ^ C ^ ((x1 ^ x2 ^ C) & (x1 ^ x3));
        long t2 = x1 ^ x2 ^ x4 ^ C ^ (x3 & x4);
        long t3 = x0 ^ x1 ^ x2 ^ C ^ ((~x0) & (x3 ^ x4));
        long t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
        x0 = t0 ^ ror(t0, 19) ^ ror(t0, 28);
        x1 = t1 ^ ror(t1, 39) ^ ror(t1, 61);
        x2 = ~(t2 ^ ror(t2, 1) ^ ror(t2, 6));
        x3 = t3 ^ ror(t3, 10) ^ ror(t3, 17);
        x4 = t4 ^ ror(t4, 7) ^ ror(t4, 41);
    }

    protected void p(int nr)
    {
        if (nr == 12)
        {
            round(0xf0L);
            round(0xe1L);
            round(0xd2L);
            round(0xc3L);
        }
        if (nr >= 8)
        {
            round(0xb4L);
            round(0xa5L);
        }
        round(0x96L);
        round(0x87L);
        round(0x78L);
        round(0x69L);
        round(0x5aL);
        round(0x4bL);
    }

    protected long pad(int i)
    {
        return 0x01L << (i << 3);
    }

    protected long loadBytes(final byte[] bytes, int inOff, int n)
    {
        return Pack.littleEndianToLong(bytes, inOff, n);
    }

    protected void setBytes(long w, byte[] bytes, int inOff, int n)
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
            x0 ^= loadBytes(input, inOff, 8);
            p(ASCON_PB_ROUNDS);
            inOff += ASCON_HASH_RATE;
            len -= ASCON_HASH_RATE;
        }
        /* absorb final plaintext block */
        x0 ^= loadBytes(input, inOff, len);
        x0 ^= pad(len);
        p(12);
    }

    protected void squeeze(byte[] output, int outOff, int len)
    {
        /* squeeze full output blocks */
        while (len > ASCON_HASH_RATE)
        {
            setBytes(x0, output, outOff, 8);
            p(ASCON_PB_ROUNDS);
            outOff += ASCON_HASH_RATE;
            len -= ASCON_HASH_RATE;
        }
        /* squeeze final output block */
        setBytes(x0, output, outOff, len);
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
