package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * implementation of Keccak based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
 * <p>
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
public class KeccakDigest
    implements ExtendedDigest
{
    private static long[] KeccakRoundConstants = new long[]{
            0x0000000000000001L,
            0x0000000000008082L,
            0x800000000000808aL,
            0x8000000080008000L,
            0x000000000000808bL,
            0x0000000080000001L,
            0x8000000080008081L,
            0x8000000000008009L,
            0x000000000000008aL,
            0x0000000000000088L,
            0x0000000080008009L,
            0x000000008000000aL,
            0x000000008000808bL,
            0x800000000000008bL,
            0x8000000000008089L,
            0x8000000000008003L,
            0x8000000000008002L,
            0x8000000000000080L,
            0x000000000000800aL,
            0x800000008000000aL,
            0x8000000080008081L,
            0x8000000000008080L,
            0x0000000080000001L,
            0x8000000080008008L};

    protected long[] state = new long[25];
    protected byte[] dataQueue = new byte[192];
    protected int rate;
    protected int bitsInQueue;
    protected int fixedOutputLength;
    protected boolean squeezing;

    public KeccakDigest()
    {
        this(288);
    }

    public KeccakDigest(int bitLength)
    {
        init(bitLength);
    }

    public KeccakDigest(KeccakDigest source)
    {
        System.arraycopy(source.state, 0, this.state, 0, source.state.length);
        System.arraycopy(source.dataQueue, 0, this.dataQueue, 0, source.dataQueue.length);
        this.rate = source.rate;
        this.bitsInQueue = source.bitsInQueue;
        this.fixedOutputLength = source.fixedOutputLength;
        this.squeezing = source.squeezing;
    }

    public String getAlgorithmName()
    {
        return "Keccak-" + fixedOutputLength;
    }

    public int getDigestSize()
    {
        return fixedOutputLength / 8;
    }

    public void update(byte in)
    {
        absorb(new byte[]{ in }, 0, 1);
    }

    public void update(byte[] in, int inOff, int len)
    {
        absorb(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
    {
        squeeze(out, outOff, fixedOutputLength);

        reset();

        return getDigestSize();
    }

    /*
     * TODO Possible API change to support partial-byte suffixes.
     */
    protected int doFinal(byte[] out, int outOff, byte partialByte, int partialBits)
    {
        if (partialBits > 0)
        {
            absorbBits(partialByte, partialBits);
        }

        squeeze(out, outOff, fixedOutputLength);

        reset();

        return getDigestSize();
    }

    public void reset()
    {
        init(fixedOutputLength);
    }

    /**
     * Return the size of block that the compression function is applied to in bytes.
     *
     * @return internal byte length of a block.
     */
    public int getByteLength()
    {
        return rate / 8;
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
        for (int i = 0; i < state.length; ++i)
        {
            state[i] = 0L;
        }
        Arrays.fill(this.dataQueue, (byte)0);
        this.bitsInQueue = 0;
        this.squeezing = false;
        this.fixedOutputLength = (1600 - rate) / 2;
    }

    protected void absorb(byte[] data, int off, int len)
    {
        if ((bitsInQueue % 8) != 0)
        {
            throw new IllegalStateException("attempt to absorb with odd length queue");
        }
        if (squeezing)
        {
            throw new IllegalStateException("attempt to absorb while squeezing");
        }

        int bytesInQueue = bitsInQueue >> 3;
        int rateBytes = rate >> 3;

        int count = 0;
        while (count < len)
        {
            if (bytesInQueue == 0 && count <= (len - rateBytes))
            {
                do
                {
                    KeccakAbsorb(data, off + count);
                    count += rateBytes;
                }
                while (count <= (len - rateBytes));
            }
            else
            {
                int partialBlock = Math.min(rateBytes - bytesInQueue, len - count);
                System.arraycopy(data, off + count, dataQueue, bytesInQueue, partialBlock);

                bytesInQueue += partialBlock;
                count += partialBlock;

                if (bytesInQueue == rateBytes)
                {
                    KeccakAbsorb(dataQueue, 0);
                    bytesInQueue = 0;
                }
            }
        }

        bitsInQueue = bytesInQueue << 3;
    }

    protected void absorbBits(int data, int bits)
    {
        if (bits < 1 || bits > 7)
        {
            throw new IllegalArgumentException("'bits' must be in the range 1 to 7");
        }
        if ((bitsInQueue % 8) != 0)
        {
            throw new IllegalStateException("attempt to absorb with odd length queue");
        }
        if (squeezing)
        {
            throw new IllegalStateException("attempt to absorb while squeezing");
        }

        int mask = (1 << bits) - 1;
        dataQueue[bitsInQueue >> 3] = (byte)(data & mask);

        // NOTE: After this, bitsInQueue is no longer a multiple of 8, so no more absorbs will work
        bitsInQueue += bits;
    }

    private void padAndSwitchToSqueezingPhase()
    {
        dataQueue[bitsInQueue >> 3] |= (byte)(1L << (bitsInQueue & 7));

        if (++bitsInQueue == rate)
        {
            KeccakAbsorb(dataQueue, 0);
            bitsInQueue = 0;
        }

        {
            int full = bitsInQueue >> 6, partial = bitsInQueue & 63;
            int off = 0;
            for (int i = 0; i < full; ++i)
            {
                state[i] ^= Pack.littleEndianToLong(dataQueue, off);
                off += 8;
            }
            if (partial > 0)
            {
                long mask = (1L << partial) - 1L;
                state[full] ^= Pack.littleEndianToLong(dataQueue, off) & mask;
            }
            state[(rate - 1) >> 6] ^= (1L << 63);
        }

        KeccakPermutation();

//        displayIntermediateValues.displayText(1, "--- Switching to squeezing phase ---");
        KeccakExtract();
        bitsInQueue = rate;

//        displayIntermediateValues.displayBytes(1, "Block available for squeezing", dataQueue, bitsInQueue / 8);
        squeezing = true;
    }

    protected void squeeze(byte[] output, int offset, long outputLength)
    {
        if (!squeezing)
        {
            padAndSwitchToSqueezingPhase();
        }
        if ((outputLength % 8) != 0)
        {
            throw new IllegalStateException("outputLength not a multiple of 8");
        }

        long i = 0;
        while (i < outputLength)
        {
            if (bitsInQueue == 0)
            {
                KeccakPermutation();
                KeccakExtract();
                bitsInQueue = rate;
//                displayIntermediateValues.displayBytes(1, "Block available for squeezing", dataQueue, bitsAvailableForSqueezing / 8);
            }
            int partialBlock = (int)Math.min((long)bitsInQueue, outputLength - i);
            System.arraycopy(dataQueue, (rate - bitsInQueue) / 8, output, offset + (int)(i / 8), partialBlock / 8);
            bitsInQueue -= partialBlock;
            i += partialBlock;
        }
    }

    private void KeccakAbsorb(byte[] data, int off)
    {
        int count = rate >> 6;
        for (int i = 0; i < count; ++i)
        {
            state[i] ^= Pack.littleEndianToLong(data, off);
            off += 8;
        }

        KeccakPermutation();
    }

    private void KeccakExtract()
    {
        Pack.longToLittleEndian(state, 0, rate >> 6, dataQueue, 0);
    }

    private void KeccakPermutation()
    {
//        displayIntermediateValues.displayStateAs64bitWords(3, "Same, with lanes as 64-bit words", state);

        for (int i = 0; i < 24; i++)
        {
//            displayIntermediateValues.displayRoundNumber(3, i);

            theta(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After theta", state);

            rho(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After rho", state);

            pi(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After pi", state);

            chi(state);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After chi", state);

            state[0] ^= KeccakRoundConstants[i];
//            iota(state, i);
//            displayIntermediateValues.displayStateAs64bitWords(3, "After iota", state);
        }
    }

    private static long leftRotate(long v, int r)
    {
        return (v << r) | (v >>> -r);
    }

    private static void theta(long[] A)
    {
        long C0 = A[0 + 0] ^ A[0 + 5] ^ A[0 + 10] ^ A[0 + 15] ^ A[0 + 20];
        long C1 = A[1 + 0] ^ A[1 + 5] ^ A[1 + 10] ^ A[1 + 15] ^ A[1 + 20];
        long C2 = A[2 + 0] ^ A[2 + 5] ^ A[2 + 10] ^ A[2 + 15] ^ A[2 + 20];
        long C3 = A[3 + 0] ^ A[3 + 5] ^ A[3 + 10] ^ A[3 + 15] ^ A[3 + 20];
        long C4 = A[4 + 0] ^ A[4 + 5] ^ A[4 + 10] ^ A[4 + 15] ^ A[4 + 20];

        long dX = leftRotate(C1, 1) ^ C4;

        A[0] ^= dX;
        A[5] ^= dX;
        A[10] ^= dX;
        A[15] ^= dX;
        A[20] ^= dX;

        dX = leftRotate(C2, 1) ^ C0;

        A[1] ^= dX;
        A[6] ^= dX;
        A[11] ^= dX;
        A[16] ^= dX;
        A[21] ^= dX;

        dX = leftRotate(C3, 1) ^ C1;

        A[2] ^= dX;
        A[7] ^= dX;
        A[12] ^= dX;
        A[17] ^= dX;
        A[22] ^= dX;

        dX = leftRotate(C4, 1) ^ C2;

        A[3] ^= dX;
        A[8] ^= dX;
        A[13] ^= dX;
        A[18] ^= dX;
        A[23] ^= dX;

        dX = leftRotate(C0, 1) ^ C3;

        A[4] ^= dX;
        A[9] ^= dX;
        A[14] ^= dX;
        A[19] ^= dX;
        A[24] ^= dX;
    }

    private static void rho(long[] A)
    {
        A[1]  = A[ 1] <<  1 | A[ 1] >>> 63;
        A[2]  = A[ 2] << 62 | A[ 2] >>>  2;
        A[3]  = A[ 3] << 28 | A[ 3] >>> 36;
        A[4]  = A[ 4] << 27 | A[ 4] >>> 37;
        A[5]  = A[ 5] << 36 | A[ 5] >>> 28;
        A[6]  = A[ 6] << 44 | A[ 6] >>> 20;
        A[7]  = A[ 7] <<  6 | A[ 7] >>> 58;
        A[8]  = A[ 8] << 55 | A[ 8] >>>  9;
        A[9]  = A[ 9] << 20 | A[ 9] >>> 44;
        A[10] = A[10] <<  3 | A[10] >>> 61;
        A[11] = A[11] << 10 | A[11] >>> 54;
        A[12] = A[12] << 43 | A[12] >>> 21;
        A[13] = A[13] << 25 | A[13] >>> 39;
        A[14] = A[14] << 39 | A[14] >>> 25;
        A[15] = A[15] << 41 | A[15] >>> 23;
        A[16] = A[16] << 45 | A[16] >>> 19;
        A[17] = A[17] << 15 | A[17] >>> 49;
        A[18] = A[18] << 21 | A[18] >>> 43;
        A[19] = A[19] <<  8 | A[19] >>> 56;
        A[20] = A[20] << 18 | A[20] >>> 46;
        A[21] = A[21] <<  2 | A[21] >>> 62;
        A[22] = A[22] << 61 | A[22] >>>  3;
        A[23] = A[23] << 56 | A[23] >>>  8;
        A[24] = A[24] << 14 | A[24] >>> 50;
    }

    private static void pi(long[] A)
    {
        long a1 = A[1];
        A[1] = A[6];
        A[6] = A[9];
        A[9] = A[22];
        A[22] = A[14];
        A[14] = A[20];
        A[20] = A[2];
        A[2] = A[12];
        A[12] = A[13];
        A[13] = A[19];
        A[19] = A[23];
        A[23] = A[15];
        A[15] = A[4];
        A[4] = A[24];
        A[24] = A[21];
        A[21] = A[8];
        A[8] = A[16];
        A[16] = A[5];
        A[5] = A[3];
        A[3] = A[18];
        A[18] = A[17];
        A[17] = A[11];
        A[11] = A[7];
        A[7] = A[10];
        A[10] = a1;
    }

    private static void chi(long[] A)
    {
        long chiC0, chiC1;

        chiC0 = A[0] ^ ((~A[1]) & A[2]);
        chiC1 = A[1] ^ ((~A[2]) & A[3]);
        A[2] ^= ((~A[3]) & A[4]);
        A[3] ^= ((~A[4]) & A[0]);
        A[4] ^= ((~A[0]) & A[1]);
        A[0] = chiC0;
        A[1] = chiC1;

        chiC0 = A[5] ^ ((~A[6]) & A[7]);
        chiC1 = A[6] ^ ((~A[7]) & A[8]);
        A[7] ^= ((~A[8]) & A[9]);
        A[8] ^= ((~A[9]) & A[5]);
        A[9] ^= ((~A[5]) & A[6]);
        A[5] = chiC0;
        A[6] = chiC1;

        chiC0 = A[10] ^ ((~A[11]) & A[12]);
        chiC1 = A[11] ^ ((~A[12]) & A[13]);
        A[12] ^= ((~A[13]) & A[14]);
        A[13] ^= ((~A[14]) & A[10]);
        A[14] ^= ((~A[10]) & A[11]);
        A[10] = chiC0;
        A[11] = chiC1;

        chiC0 = A[15] ^ ((~A[16]) & A[17]);
        chiC1 = A[16] ^ ((~A[17]) & A[18]);
        A[17] ^= ((~A[18]) & A[19]);
        A[18] ^= ((~A[19]) & A[15]);
        A[19] ^= ((~A[15]) & A[16]);
        A[15] = chiC0;
        A[16] = chiC1;

        chiC0 = A[20] ^ ((~A[21]) & A[22]);
        chiC1 = A[21] ^ ((~A[22]) & A[23]);
        A[22] ^= ((~A[23]) & A[24]);
        A[23] ^= ((~A[24]) & A[20]);
        A[24] ^= ((~A[20]) & A[21]);
        A[20] = chiC0;
        A[21] = chiC1;
    }

}
