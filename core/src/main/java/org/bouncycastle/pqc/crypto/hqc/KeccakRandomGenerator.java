package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.util.Arrays;

/**
 * implementation of Incremental version for Keccak
 */
class KeccakRandomGenerator
{
    private static long[] KeccakRoundConstants = new long[]{0x0000000000000001L, 0x0000000000008082L,
        0x800000000000808aL, 0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L,
        0x8000000000008009L, 0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L, 0x8000000000008002L,
        0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L, 0x8000000000008080L,
        0x0000000080000001L, 0x8000000080008008L};

    protected long[] state = new long[26];
    protected byte[] dataQueue = new byte[192];
    protected int rate;
    protected int bitsInQueue;
    protected int fixedOutputLength;

    public KeccakRandomGenerator()
    {
        this(288);
    }

    public KeccakRandomGenerator(int bitLength)
    {
        init(bitLength);
    }

    private void init(int bitLength)
    {
        switch (bitLength)
        {
        case 128:
        case 224:
        case 256:
        case 288:
        case 384:
        case 512:
            initSponge(1600 - (bitLength << 1));
            break;
        default:
            throw new IllegalArgumentException("bitLength must be one of 128, 224, 256, 288, 384, or 512.");
        }
    }

    private void initSponge(int rate)
    {
        if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0))
        {
            throw new IllegalStateException("invalid rate value");
        }

        this.rate = rate;
        Arrays.fill(state, 0L);
        Arrays.fill(this.dataQueue, (byte)0);
        this.bitsInQueue = 0;
        this.fixedOutputLength = (1600 - rate) / 2;
    }

    // TODO Somehow just use the one in KeccakDigest
    private static void keccakPermutation(long[] A)
    {
        long a00 = A[0], a01 = A[1], a02 = A[2], a03 = A[3], a04 = A[4];
        long a05 = A[5], a06 = A[6], a07 = A[7], a08 = A[8], a09 = A[9];
        long a10 = A[10], a11 = A[11], a12 = A[12], a13 = A[13], a14 = A[14];
        long a15 = A[15], a16 = A[16], a17 = A[17], a18 = A[18], a19 = A[19];
        long a20 = A[20], a21 = A[21], a22 = A[22], a23 = A[23], a24 = A[24];

        for (int i = 0; i < 24; i++)
        {
            // theta
            long c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
            long c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
            long c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
            long c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
            long c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;

            long d1 = (c1 << 1 | c1 >>> -1) ^ c4;
            long d2 = (c2 << 1 | c2 >>> -1) ^ c0;
            long d3 = (c3 << 1 | c3 >>> -1) ^ c1;
            long d4 = (c4 << 1 | c4 >>> -1) ^ c2;
            long d0 = (c0 << 1 | c0 >>> -1) ^ c3;

            a00 ^= d1;
            a05 ^= d1;
            a10 ^= d1;
            a15 ^= d1;
            a20 ^= d1;
            a01 ^= d2;
            a06 ^= d2;
            a11 ^= d2;
            a16 ^= d2;
            a21 ^= d2;
            a02 ^= d3;
            a07 ^= d3;
            a12 ^= d3;
            a17 ^= d3;
            a22 ^= d3;
            a03 ^= d4;
            a08 ^= d4;
            a13 ^= d4;
            a18 ^= d4;
            a23 ^= d4;
            a04 ^= d0;
            a09 ^= d0;
            a14 ^= d0;
            a19 ^= d0;
            a24 ^= d0;

            // rho/pi
            c1 = a01 << 1 | a01 >>> 63;
            a01 = a06 << 44 | a06 >>> 20;
            a06 = a09 << 20 | a09 >>> 44;
            a09 = a22 << 61 | a22 >>> 3;
            a22 = a14 << 39 | a14 >>> 25;
            a14 = a20 << 18 | a20 >>> 46;
            a20 = a02 << 62 | a02 >>> 2;
            a02 = a12 << 43 | a12 >>> 21;
            a12 = a13 << 25 | a13 >>> 39;
            a13 = a19 << 8 | a19 >>> 56;
            a19 = a23 << 56 | a23 >>> 8;
            a23 = a15 << 41 | a15 >>> 23;
            a15 = a04 << 27 | a04 >>> 37;
            a04 = a24 << 14 | a24 >>> 50;
            a24 = a21 << 2 | a21 >>> 62;
            a21 = a08 << 55 | a08 >>> 9;
            a08 = a16 << 45 | a16 >>> 19;
            a16 = a05 << 36 | a05 >>> 28;
            a05 = a03 << 28 | a03 >>> 36;
            a03 = a18 << 21 | a18 >>> 43;
            a18 = a17 << 15 | a17 >>> 49;
            a17 = a11 << 10 | a11 >>> 54;
            a11 = a07 << 6 | a07 >>> 58;
            a07 = a10 << 3 | a10 >>> 61;
            a10 = c1;

            // chi
            c0 = a00 ^ (~a01 & a02);
            c1 = a01 ^ (~a02 & a03);
            a02 ^= ~a03 & a04;
            a03 ^= ~a04 & a00;
            a04 ^= ~a00 & a01;
            a00 = c0;
            a01 = c1;

            c0 = a05 ^ (~a06 & a07);
            c1 = a06 ^ (~a07 & a08);
            a07 ^= ~a08 & a09;
            a08 ^= ~a09 & a05;
            a09 ^= ~a05 & a06;
            a05 = c0;
            a06 = c1;

            c0 = a10 ^ (~a11 & a12);
            c1 = a11 ^ (~a12 & a13);
            a12 ^= ~a13 & a14;
            a13 ^= ~a14 & a10;
            a14 ^= ~a10 & a11;
            a10 = c0;
            a11 = c1;

            c0 = a15 ^ (~a16 & a17);
            c1 = a16 ^ (~a17 & a18);
            a17 ^= ~a18 & a19;
            a18 ^= ~a19 & a15;
            a19 ^= ~a15 & a16;
            a15 = c0;
            a16 = c1;

            c0 = a20 ^ (~a21 & a22);
            c1 = a21 ^ (~a22 & a23);
            a22 ^= ~a23 & a24;
            a23 ^= ~a24 & a20;
            a24 ^= ~a20 & a21;
            a20 = c0;
            a21 = c1;

            // iota
            a00 ^= KeccakRoundConstants[i];
        }

        A[0] = a00;
        A[1] = a01;
        A[2] = a02;
        A[3] = a03;
        A[4] = a04;
        A[5] = a05;
        A[6] = a06;
        A[7] = a07;
        A[8] = a08;
        A[9] = a09;
        A[10] = a10;
        A[11] = a11;
        A[12] = a12;
        A[13] = a13;
        A[14] = a14;
        A[15] = a15;
        A[16] = a16;
        A[17] = a17;
        A[18] = a18;
        A[19] = a19;
        A[20] = a20;
        A[21] = a21;
        A[22] = a22;
        A[23] = a23;
        A[24] = a24;
    }

    private void keccakIncAbsorb(byte[] input, int inputLen)
    {
        int count = 0;
        int rateBytes = rate >> 3;
        while (inputLen + state[25] >= rateBytes)
        {
            for (int i = 0; i < rateBytes - state[25]; i++)
            {
                int tmp = (int)(state[25] + i) >> 3;
                state[tmp] ^= toUnsignedLong(input[i + count] & 0xff) << (8 * ((state[25] + i) & 0x07));
            }
            inputLen -= rateBytes - state[25];
            count += rateBytes - state[25];
            state[25] = 0;
            keccakPermutation(state);
        }

        for (int i = 0; i < inputLen; i++)
        {
            int tmp = (int)(state[25] + i) >> 3;
            state[tmp] ^= toUnsignedLong(input[i + count] & 0xff) << (8 * ((state[25] + i) & 0x07));
        }

        state[25] += inputLen;
    }

    private void keccakIncFinalize(int p)
    {
        int rateBytes = rate >> 3;

        state[(int)state[25] >> 3] ^= toUnsignedLong(p) << (8 * ((state[25]) & 0x07));
        state[(rateBytes - 1) >> 3] ^= toUnsignedLong(128) << (8 * ((rateBytes - 1) & 0x07));


        state[25] = 0;
    }

    private void keccakIncSqueeze(byte[] output, int outLen)
    {
        int rateBytes = rate >> 3;
        int i;
        for (i = 0; i < outLen && i < state[25]; i++)
        {
            output[i] = (byte)(state[(int)((rateBytes - state[25] + i) >> 3)] >> (8 * ((rateBytes - state[25] + i) & 0x07)));
        }

        int count = i;
        outLen -= i;
        state[25] -= i;

        while (outLen > 0)
        {
            keccakPermutation(state);

            for (i = 0; i < outLen && i < rateBytes; i++)
            {
                output[count + i] = (byte)(state[i >> 3] >> (8 * (i & 0x07)));
            }
            count = count + i;
            outLen -= i;
            state[25] = rateBytes - i;
        }
    }

    public void squeeze(byte[] output, int outLen)
    {
        keccakIncSqueeze(output, outLen);
    }

    public void randomGeneratorInit(byte[] entropyInput, byte[] personalizationString, int entropyLen, int perLen)
    {
        byte[] domain = new byte[]{1};
        keccakIncAbsorb(entropyInput, entropyLen);
        keccakIncAbsorb(personalizationString, perLen);
        keccakIncAbsorb(domain, domain.length);
        keccakIncFinalize(0x1F);
    }

    public void seedExpanderInit(byte[] seed, int seedLen)
    {
        byte[] domain = new byte[]{2};
        keccakIncAbsorb(seed, seedLen);
        keccakIncAbsorb(domain, 1);
        keccakIncFinalize(0x1F);
    }

    public void expandSeed(byte[] output, int outLen)
    {
        int r = outLen & 7;
        keccakIncSqueeze(output, outLen - r);

        if (r != 0)
        {
            byte[] tmp = new byte[8];
            keccakIncSqueeze(tmp, 8);
            System.arraycopy(tmp, 0, output, outLen - r, r);
        }
    }

    public void SHAKE256_512_ds(byte[] output, byte[] input, int inLen, byte[] domain)
    {
        Arrays.fill(state, 0L);
        keccakIncAbsorb(input, inLen);
        keccakIncAbsorb(domain, domain.length);
        keccakIncFinalize(0x1F);
        keccakIncSqueeze(output, 512 / 8);
    }

    private static long toUnsignedLong(int x)
    {
        return x & 0xffffffffL;
    }
}
