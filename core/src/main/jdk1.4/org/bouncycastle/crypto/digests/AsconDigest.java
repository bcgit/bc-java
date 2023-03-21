package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;

/* ASCON v1.2 Digest, https://ascon.iaik.tugraz.at/ .
 * <p>
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
 * <p>
 * ASCON v1.2 Digest with reference to C Reference Impl from: https://github.com/ascon/ascon-c .
 */
public class AsconDigest
    implements Digest
{
    public static class AsconParameters
    {
        public static final AsconParameters AsconHash = new AsconParameters(0);
        public static final AsconParameters AsconHashA = new AsconParameters(1);

        private final int ord;

        AsconParameters(int ord)
        {
            this.ord = ord;
        }
    }

    AsconParameters asconParameters;

    public AsconDigest(AsconParameters parameters)
    {
        this.asconParameters = parameters;
        switch (parameters.ord)
        {
        case 0: //AsconHash:
            ASCON_PB_ROUNDS = 12;
            algorithmName = "Ascon-Hash";
            break;
        case 1: //AsconHashA:
            ASCON_PB_ROUNDS = 8;
            algorithmName = "Ascon-HashA";
            break;
        default:
            throw new IllegalArgumentException("Invalid parameter settings for Ascon Hash");
        }
        reset();
    }

    private final String algorithmName;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private long x0;
    private long x1;
    private long x2;
    private long x3;
    private long x4;
    private final int CRYPTO_BYTES = 32;
    private final int ASCON_PB_ROUNDS;

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
        return 0x80L << (56 - (i << 3));
    }

    private long LOADBYTES(final byte[] bytes, int inOff, int n)
    {
        long x = 0;
        for (int i = 0; i < n; ++i)
        {
            x |= (bytes[i + inOff] & 0xFFL) << ((7 - i) << 3);
        }
        return x;
    }

    private void STOREBYTES(byte[] bytes, int inOff, long w, int n)
    {
        for (int i = 0; i < n; ++i)
        {
            bytes[i + inOff] = (byte)(w >>> ((7 - i) << 3));
        }
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
            x0 ^= LOADBYTES(input, inOff, 8);
            P(ASCON_PB_ROUNDS);
            inOff += ASCON_HASH_RATE;
            len -= ASCON_HASH_RATE;
        }
        /* absorb final plaintext block */
        x0 ^= LOADBYTES(input, inOff, len);
        x0 ^= PAD(len);
        int ASCON_PA_ROUNDS = 12;
        P(ASCON_PA_ROUNDS);
        /* squeeze full output blocks */
        len = CRYPTO_BYTES;
        while (len > ASCON_HASH_RATE)
        {
            STOREBYTES(output, outOff, x0, 8);
            P(ASCON_PB_ROUNDS);
            outOff += ASCON_HASH_RATE;
            len -= ASCON_HASH_RATE;
        }
        /* squeeze final output block */
        STOREBYTES(output, outOff, x0, len);
        reset();
        return CRYPTO_BYTES;
    }

    @Override
    public void reset()
    {
        buffer.reset();
        /* initialize */
        switch (asconParameters.ord)
        {
        case 1: //AsconHashA:
            x0 = 92044056785660070L;
            x1 = 8326807761760157607L;
            x2 = 3371194088139667532L;
            x3 = -2956994353054992515L;
            x4 = -6828509670848688761L;
            break;
        case 0: //AsconHash:
            x0 = -1255492011513352131L;
            x1 = -8380609354527731710L;
            x2 = -5437372128236807582L;
            x3 = 4834782570098516968L;
            x4 = 3787428097924915520L;
            break;
        }
    }
}
