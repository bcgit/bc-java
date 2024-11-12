package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Pack;

/**
 * ASCON v1.2 Digest, https://ascon.iaik.tugraz.at/ .
 * <p>
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
 * <p>
 * ASCON v1.2 Digest with reference to C Reference Impl from: https://github.com/ascon/ascon-c .
 *
 */
public class AsconHash256Digest
    implements ExtendedDigest
{
    public AsconHash256Digest()
    {
        reset();
    }

    private final String algorithmName = "Ascon Hash 256";
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private long x0;
    private long x1;
    private long x2;
    private long x3;
    private long x4;
    private final int CRYPTO_BYTES = 32;
    private final int ASCON_PB_ROUNDS = 12;

    private long ROR(long x, int n)
    {
        return x >>> n | x << (64 - n);
    }

    private void ROUND(long C)
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

    private void P(int nr)
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

    private long PAD(int i)
    {
        return 0x01L << (i << 3);
    }

    @Override
    public String getAlgorithmName()
    {
        return algorithmName;
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

    @Override
    public int doFinal(byte[] output, int outOff)
    {
        if (CRYPTO_BYTES + outOff > output.length)
        {
            throw new OutputLengthException("output buffer is too short");
        }
        byte[] input = buffer.toByteArray();
        int len = buffer.size();
        int inOff = 0;
        /* absorb full plaintext blocks */
        int ASCON_HASH_RATE = 8;
        while (len >= ASCON_HASH_RATE)
        {
            x0 ^= Pack.littleEndianToLong(input, inOff, 8);
            P(ASCON_PB_ROUNDS);
            inOff += ASCON_HASH_RATE;
            len -= ASCON_HASH_RATE;
        }
        /* absorb final plaintext block */
        x0 ^= Pack.littleEndianToLong(input, inOff, len);
        x0 ^= PAD(len);
        P(12);
        /* squeeze full output blocks */
        len = CRYPTO_BYTES;
        while (len > ASCON_HASH_RATE)
        {
            Pack.longToLittleEndian(x0, output, outOff, 8);
            P(ASCON_PB_ROUNDS);
            outOff += ASCON_HASH_RATE;
            len -= ASCON_HASH_RATE;
        }
        /* squeeze final output block */
        Pack.longToLittleEndian(x0, output, outOff, len);
        reset();
        return CRYPTO_BYTES;
    }

    @Override
    public void reset()
    {
        buffer.reset();
        /* initialize */
        x0 = -7269279749984954751L;
        x1 = 5459383224871899602L;
        x2 = -5880230600644446182L;
        x3 = 4359436768738168243L;
        x4 = 1899470422303676269L;
    }
}
