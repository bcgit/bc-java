package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * Reference implementation of national ukrainian standard of hashing transformation DSTU7564.
 * Thanks to Roman Oliynykov' native C implementation:
 * https://github.com/Roman-Oliynykov/Kupyna-reference
 */
public class DSTU7564Digest
    implements ExtendedDigest, Memoable
{
    private static final int ROWS = 8;
    private static final int BITS_IN_BYTE = 8;

    /* Number of 8-byte words in operating state for <= 256-bit hash codes */
    private static final int NB_512 = 8;

    /* Number of 8-byte words in operating state for <= 512-bit hash codes */
    private static final int NB_1024 = 16;

    /* Number of rounds for 512-bit state */
    private static final int NR_512 = 10;

    /* Number of rounds for 1024-bit state */
    private static final int NR_1024 = 14;

    private static final int STATE_BYTES_SIZE_512 = ROWS * NB_512;
    private static final int STATE_BYTES_SIZE_1024 = ROWS * NB_1024;

    private int hashSize;
    private int blockSize;

    private int columns;
    private int rounds;

    private byte[][] state;

    private byte[][] tempState1;
    private byte[][] tempState2;

    private long[] tempLongBuffer;

    // TODO Guard against 'inputBlocks' overflow (2^64 blocks)
    private long inputBlocks;
    private int bufOff;
    private byte[] buf;

    public DSTU7564Digest(DSTU7564Digest digest)
    {
        copyIn(digest);
    }

    private void copyIn(DSTU7564Digest digest)
    {
        this.hashSize = digest.hashSize;
        this.blockSize = digest.blockSize;

        this.columns = digest.columns;
        this.rounds = digest.rounds;

        this.state = Arrays.clone(digest.state);

        this.tempState1 = Arrays.clone(digest.tempState1);
        this.tempState2 = Arrays.clone(digest.tempState2);

        this.tempLongBuffer = Arrays.clone(digest.tempLongBuffer);

        this.inputBlocks = digest.inputBlocks;
        this.bufOff = digest.bufOff;
        this.buf = Arrays.clone(digest.buf);
    }

    public DSTU7564Digest(int hashSizeBits)
    {
        if (hashSizeBits == 256 || hashSizeBits == 384 || hashSizeBits == 512)
        {
            this.hashSize = hashSizeBits / BITS_IN_BYTE;
        }
        else
        {
            throw new IllegalArgumentException("Hash size is not recommended. Use 256/384/512 instead");
        }

        if (hashSizeBits > 256)
        {
            this.blockSize = 1024 / BITS_IN_BYTE;
            this.columns = NB_1024;
            this.rounds = NR_1024;
            this.state = new byte[STATE_BYTES_SIZE_1024][];
        }
        else
        {
            this.blockSize = 512 / BITS_IN_BYTE;
            this.columns = NB_512;
            this.rounds = NR_512;
            this.state = new byte[STATE_BYTES_SIZE_512][];
        }
        for (int bufferIndex = 0; bufferIndex < state.length; bufferIndex++)
        {
            this.state[bufferIndex] = new byte[columns];
        }

        this.state[0][0] = (byte)state.length; // Defined in standard

        this.tempState1 = new byte[columns][];
        this.tempState2 = new byte[columns][];

        for (int col = 0; col < columns; col++)
        {
            this.tempState1[col] = new byte[ROWS];
            this.tempState2[col] = new byte[ROWS];
        }

        this.tempLongBuffer = new long[columns];
        this.buf = new byte[blockSize];
    }

    public String getAlgorithmName()
    {
        return "DSTU7564";
    }

    public int getDigestSize()
    {
        return hashSize;
    }

    public int getByteLength()
    {
        return blockSize;
    }

    public void update(byte in)
    {
        buf[bufOff++] = in;
        if (bufOff == blockSize)
        {
            processBlock(buf, 0);
            bufOff = 0;
            ++inputBlocks;
        }
    }

    public void update(byte[] in, int inOff, int len)
    {
        while (bufOff != 0 && len > 0)
        {
            update(in[inOff++]);
            len--;
        }

        if (len > 0)
        {
            while (len > blockSize)
            {
                processBlock(in, inOff);
                inOff += blockSize;
                len -= blockSize;
                ++inputBlocks;
            }

            while (len > 0)
            {
                update(in[inOff++]);
                len--;
            }
        }
    }

    public int doFinal(byte[] out, int outOff)
    {
        // Apply padding: terminator byte and 96-bit length field
        {
            int inputBytes = bufOff;
            buf[bufOff++] = (byte)0x80;

            int lenPos = blockSize - 12;
            if (bufOff > lenPos)
            {
                while (bufOff < blockSize)
                {
                    buf[bufOff++] = 0;
                }
                bufOff = 0;
                processBlock(buf, 0);
            }

            while (bufOff < lenPos)
            {
                buf[bufOff++] = 0;
            }

            long c = ((inputBlocks & 0xFFFFFFFFL) * blockSize + inputBytes) << 3;
            Pack.intToLittleEndian((int)c, buf, bufOff);
            bufOff += 4;
            c >>>= 32;
            c += ((inputBlocks >>> 32) * blockSize) << 3;
            Pack.longToLittleEndian((int)c, buf, bufOff);
//            bufOff += 8;
            processBlock(buf, 0);
        }

        byte[][] temp = new byte[state.length][];

        for (int bufferIndex = 0; bufferIndex < state.length; bufferIndex++)
        {
            temp[bufferIndex] = new byte[ROWS];

            System.arraycopy(state[bufferIndex], 0, temp[bufferIndex], 0, ROWS);
        }

        for (int roundIndex = 0; roundIndex < rounds; roundIndex++)
        {
            /* AddRoundConstants */
            for (int columnIndex = 0; columnIndex < columns; columnIndex++)
            {
                temp[columnIndex][0] ^= (byte)((columnIndex * 0x10) ^ roundIndex); // Defined in standard
            }

            subBytes(temp);
            shiftRows(temp);
            mixColumns(temp);
        }

        for (int rowIndex = 0; rowIndex < ROWS; rowIndex++)
        {
            for (int columnIndex = 0; columnIndex < columns; columnIndex++)
            {
                state[columnIndex][rowIndex] ^= temp[columnIndex][rowIndex];
            }
        }

        byte[] stateBuffer = new byte[ROWS * columns];
        int stateLineIndex = 0;

        for (int columnIndex = 0; columnIndex < columns; columnIndex++)
        {
            for (int rowIndex = 0; rowIndex < ROWS; rowIndex++)
            {

                stateBuffer[stateLineIndex] = state[columnIndex][rowIndex];
                stateLineIndex++;
            }
        }

        System.arraycopy(stateBuffer, stateBuffer.length - hashSize, out, outOff, hashSize);

        reset();
        
        return hashSize;
    }

    public void reset()
    {
        for (int bufferIndex = 0; bufferIndex < state.length; bufferIndex++)
        {
            state[bufferIndex] = new byte[columns];
        }

        state[0][0] = (byte)state.length;

        inputBlocks = 0;
        bufOff = 0;
        
        Arrays.fill(buf, (byte)0);
    }

    private void processBlock(byte[] input, int inOff)
    {
        int pos = inOff;
        for (int col = 0; col < columns; col++)
        {
            byte[] S = state[col], T1 = tempState1[col], T2 = tempState2[col];
            for (int row = 0; row < ROWS; row++)
            {
                byte inVal = input[pos++];
                T1[row] = (byte)(S[row] ^ inVal);
                T2[row] = inVal;
            }
        }

        P(); // mixing tempState1
        Q(); // mixing tempState2

        for (int col = 0; col < columns; col++)
        {
            byte[] S = state[col], T1 = tempState1[col], T2 = tempState2[col];
            for (int row = 0; row < ROWS; row++)
            {
                S[row] ^= (byte)(T1[row] ^ T2[row]);
            }
        }
    }

    private void P()
    {
        for (int roundIndex = 0; roundIndex < rounds; roundIndex++)
        {
            /* AddRoundConstants */
            for (int columnIndex = 0; columnIndex < columns; columnIndex++)
            {
                tempState1[columnIndex][0] ^= (byte)((columnIndex * 0x10) ^ roundIndex); // Defined in standard
            }

            subBytes(tempState1);
            shiftRows(tempState1);
            mixColumns(tempState1);
        }
    }

    private void Q()
    {
        for (int roundIndex = 0; roundIndex < rounds; roundIndex++)
        {
            /* AddRoundConstantsQ */
            {
                long rc = ((long)(((columns - 1) << 4) ^ roundIndex) << 56) | 0x00F0F0F0F0F0F0F3L;

                for (int columnIndex = 0; columnIndex < columns; columnIndex++)
                {
                    tempLongBuffer[columnIndex] = Pack.littleEndianToLong(tempState2[columnIndex], 0);

                    tempLongBuffer[columnIndex] += rc;
                    rc -= 0x1000000000000000L;

                    Pack.longToLittleEndian(tempLongBuffer[columnIndex], tempState2[columnIndex], 0);
                }
            }

            subBytes(tempState2);
            shiftRows(tempState2);
            mixColumns(tempState2);
        }
    }

    private static long mixColumn(long c)
    {
        // Calculate column multiplied by powers of 'x'
        long x0 = c;
        long x1 = ((x0 & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((x0 & 0x8080808080808080L) >>> 7) * 0x1DL);
        long x2 = ((x1 & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((x1 & 0x8080808080808080L) >>> 7) * 0x1DL);
        long x3 = ((x2 & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((x2 & 0x8080808080808080L) >>> 7) * 0x1DL);

        // Calculate products with circulant matrix from (0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04)
//        long m0 = x0;
//        long m1 = x0;
//        long m2 = x0 ^ x2;
//        long m3 = x0;
//        long m4 = x3;
//        long m5 = x1 ^ x2;
//        long m6 = x0 ^ x1 ^ x2;
//        long m7 = x2;

        // Assemble the rotated products
//        return m0
//            ^ ((m1 << 56) | (m1 >>>  8))
//            ^ ((m2 << 48) | (m2 >>> 16))
//            ^ ((m3 << 40) | (m3 >>> 24))
//            ^ ((m4 << 32) | (m4 >>> 32))
//            ^ ((m5 << 24) | (m5 >>> 40))
//            ^ ((m6 << 16) | (m6 >>> 48))
//            ^ ((m7 <<  8) | (m7 >>> 56));

        x1 ^= x2;
        x1 ^= ((x1 <<  8) | (x1 >>> 56));
        x1 ^= x0;

        x0 ^= ((x0 << 56) | (x0 >>>  8));
        x0 ^= ((x0 << 16) | (x0 >>> 48));
        x0 ^= x2;

        return ((x0 << 48) | (x0 >>> 16))
            ^  ((x3 << 32) | (x3 >>> 32))
            ^  ((x1 << 16) | (x1 >>> 48))
            ^  ((x2 <<  8) | (x2 >>> 56));
    }

    private void mixColumns(byte[][] state)
    {
        for (int col = 0; col < columns; ++col)
        {
            long colVal = Pack.littleEndianToLong(state[col], 0);
            colVal = mixColumn(colVal);
            Pack.longToLittleEndian(colVal, state[col], 0);
        }
    }

    private void shiftRows(byte[][] state)
    {
        switch (columns)
        {
        case NB_512:
        {
            long c0 = Pack.littleEndianToLong(state[0], 0);
            long c1 = Pack.littleEndianToLong(state[1], 0);
            long c2 = Pack.littleEndianToLong(state[2], 0);
            long c3 = Pack.littleEndianToLong(state[3], 0);
            long c4 = Pack.littleEndianToLong(state[4], 0);
            long c5 = Pack.littleEndianToLong(state[5], 0);
            long c6 = Pack.littleEndianToLong(state[6], 0);
            long c7 = Pack.littleEndianToLong(state[7], 0);
            long d;

            d = (c0 ^ c4) & 0xFFFFFFFF00000000L; c0 ^= d; c4 ^= d;
            d = (c1 ^ c5) & 0x00FFFFFFFF000000L; c1 ^= d; c5 ^= d;
            d = (c2 ^ c6) & 0x0000FFFFFFFF0000L; c2 ^= d; c6 ^= d;
            d = (c3 ^ c7) & 0x000000FFFFFFFF00L; c3 ^= d; c7 ^= d;

            d = (c0 ^ c2) & 0xFFFF0000FFFF0000L; c0 ^= d; c2 ^= d;
            d = (c1 ^ c3) & 0x00FFFF0000FFFF00L; c1 ^= d; c3 ^= d;
            d = (c4 ^ c6) & 0xFFFF0000FFFF0000L; c4 ^= d; c6 ^= d;
            d = (c5 ^ c7) & 0x00FFFF0000FFFF00L; c5 ^= d; c7 ^= d;

            d = (c0 ^ c1) & 0xFF00FF00FF00FF00L; c0 ^= d; c1 ^= d;
            d = (c2 ^ c3) & 0xFF00FF00FF00FF00L; c2 ^= d; c3 ^= d;
            d = (c4 ^ c5) & 0xFF00FF00FF00FF00L; c4 ^= d; c5 ^= d;
            d = (c6 ^ c7) & 0xFF00FF00FF00FF00L; c6 ^= d; c7 ^= d;

            Pack.longToLittleEndian(c0, state[0], 0);
            Pack.longToLittleEndian(c1, state[1], 0);
            Pack.longToLittleEndian(c2, state[2], 0);
            Pack.longToLittleEndian(c3, state[3], 0);
            Pack.longToLittleEndian(c4, state[4], 0);
            Pack.longToLittleEndian(c5, state[5], 0);
            Pack.longToLittleEndian(c6, state[6], 0);
            Pack.longToLittleEndian(c7, state[7], 0);
            break;
        }
        case NB_1024:
        {
            long c00 = Pack.littleEndianToLong(state[0], 0);
            long c01 = Pack.littleEndianToLong(state[1], 0);
            long c02 = Pack.littleEndianToLong(state[2], 0);
            long c03 = Pack.littleEndianToLong(state[3], 0);
            long c04 = Pack.littleEndianToLong(state[4], 0);
            long c05 = Pack.littleEndianToLong(state[5], 0);
            long c06 = Pack.littleEndianToLong(state[6], 0);
            long c07 = Pack.littleEndianToLong(state[7], 0);
            long c08 = Pack.littleEndianToLong(state[8], 0);
            long c09 = Pack.littleEndianToLong(state[9], 0);
            long c10 = Pack.littleEndianToLong(state[10], 0);
            long c11 = Pack.littleEndianToLong(state[11], 0);
            long c12 = Pack.littleEndianToLong(state[12], 0);
            long c13 = Pack.littleEndianToLong(state[13], 0);
            long c14 = Pack.littleEndianToLong(state[14], 0);
            long c15 = Pack.littleEndianToLong(state[15], 0);
            long d;

            // NOTE: Row 7 is shifted by 11

            d = (c00 ^ c08) & 0xFF00000000000000L; c00 ^= d; c08 ^= d;
            d = (c01 ^ c09) & 0xFF00000000000000L; c01 ^= d; c09 ^= d;
            d = (c02 ^ c10) & 0xFFFF000000000000L; c02 ^= d; c10 ^= d;
            d = (c03 ^ c11) & 0xFFFFFF0000000000L; c03 ^= d; c11 ^= d;
            d = (c04 ^ c12) & 0xFFFFFFFF00000000L; c04 ^= d; c12 ^= d;
            d = (c05 ^ c13) & 0x00FFFFFFFF000000L; c05 ^= d; c13 ^= d;
            d = (c06 ^ c14) & 0x00FFFFFFFFFF0000L; c06 ^= d; c14 ^= d;
            d = (c07 ^ c15) & 0x00FFFFFFFFFFFF00L; c07 ^= d; c15 ^= d;

            d = (c00 ^ c04) & 0x00FFFFFF00000000L; c00 ^= d; c04 ^= d;
            d = (c01 ^ c05) & 0xFFFFFFFFFF000000L; c01 ^= d; c05 ^= d;
            d = (c02 ^ c06) & 0xFF00FFFFFFFF0000L; c02 ^= d; c06 ^= d;
            d = (c03 ^ c07) & 0xFF0000FFFFFFFF00L; c03 ^= d; c07 ^= d;
            d = (c08 ^ c12) & 0x00FFFFFF00000000L; c08 ^= d; c12 ^= d;
            d = (c09 ^ c13) & 0xFFFFFFFFFF000000L; c09 ^= d; c13 ^= d;
            d = (c10 ^ c14) & 0xFF00FFFFFFFF0000L; c10 ^= d; c14 ^= d;
            d = (c11 ^ c15) & 0xFF0000FFFFFFFF00L; c11 ^= d; c15 ^= d;

            d = (c00 ^ c02) & 0xFFFF0000FFFF0000L; c00 ^= d; c02 ^= d;
            d = (c01 ^ c03) & 0x00FFFF0000FFFF00L; c01 ^= d; c03 ^= d;
            d = (c04 ^ c06) & 0xFFFF0000FFFF0000L; c04 ^= d; c06 ^= d;
            d = (c05 ^ c07) & 0x00FFFF0000FFFF00L; c05 ^= d; c07 ^= d;
            d = (c08 ^ c10) & 0xFFFF0000FFFF0000L; c08 ^= d; c10 ^= d;
            d = (c09 ^ c11) & 0x00FFFF0000FFFF00L; c09 ^= d; c11 ^= d;
            d = (c12 ^ c14) & 0xFFFF0000FFFF0000L; c12 ^= d; c14 ^= d;
            d = (c13 ^ c15) & 0x00FFFF0000FFFF00L; c13 ^= d; c15 ^= d;

            d = (c00 ^ c01) & 0xFF00FF00FF00FF00L; c00 ^= d; c01 ^= d;
            d = (c02 ^ c03) & 0xFF00FF00FF00FF00L; c02 ^= d; c03 ^= d;
            d = (c04 ^ c05) & 0xFF00FF00FF00FF00L; c04 ^= d; c05 ^= d;
            d = (c06 ^ c07) & 0xFF00FF00FF00FF00L; c06 ^= d; c07 ^= d;
            d = (c08 ^ c09) & 0xFF00FF00FF00FF00L; c08 ^= d; c09 ^= d;
            d = (c10 ^ c11) & 0xFF00FF00FF00FF00L; c10 ^= d; c11 ^= d;
            d = (c12 ^ c13) & 0xFF00FF00FF00FF00L; c12 ^= d; c13 ^= d;
            d = (c14 ^ c15) & 0xFF00FF00FF00FF00L; c14 ^= d; c15 ^= d;

            Pack.longToLittleEndian(c00, state[0], 0);
            Pack.longToLittleEndian(c01, state[1], 0);
            Pack.longToLittleEndian(c02, state[2], 0);
            Pack.longToLittleEndian(c03, state[3], 0);
            Pack.longToLittleEndian(c04, state[4], 0);
            Pack.longToLittleEndian(c05, state[5], 0);
            Pack.longToLittleEndian(c06, state[6], 0);
            Pack.longToLittleEndian(c07, state[7], 0);
            Pack.longToLittleEndian(c08, state[8], 0);
            Pack.longToLittleEndian(c09, state[9], 0);
            Pack.longToLittleEndian(c10, state[10], 0);
            Pack.longToLittleEndian(c11, state[11], 0);
            Pack.longToLittleEndian(c12, state[12], 0);
            Pack.longToLittleEndian(c13, state[13], 0);
            Pack.longToLittleEndian(c14, state[14], 0);
            Pack.longToLittleEndian(c15, state[15], 0);
            break;
        }
        default:
        {
            throw new IllegalStateException("unsupported state size: only 512/1024 are allowed");
        }
        }
    }

    private void subBytes(byte[][] state)
    {
        for (int columnIndex = 0; columnIndex < columns; columnIndex++)
        {
            byte[] c = state[columnIndex];
            
            byte c0 = c[0], c1 = c[1], c2 = c[2], c3 = c[3];
            byte c4 = c[4], c5 = c[5], c6 = c[6], c7 = c[7];

            c[0] = S0[c0 & 0xFF];
            c[1] = S1[c1 & 0xFF];
            c[2] = S2[c2 & 0xFF];
            c[3] = S3[c3 & 0xFF];
            c[4] = S0[c4 & 0xFF];
            c[5] = S1[c5 & 0xFF];
            c[6] = S2[c6 & 0xFF];
            c[7] = S3[c7 & 0xFF];
        }
    }

    private static final byte[] S0 = new byte[]{ (byte)0xa8, (byte)0x43, (byte)0x5f, (byte)0x06, (byte)0x6b, (byte)0x75,
        (byte)0x6c, (byte)0x59, (byte)0x71, (byte)0xdf, (byte)0x87, (byte)0x95, (byte)0x17, (byte)0xf0, (byte)0xd8,
        (byte)0x09, (byte)0x6d, (byte)0xf3, (byte)0x1d, (byte)0xcb, (byte)0xc9, (byte)0x4d, (byte)0x2c, (byte)0xaf,
        (byte)0x79, (byte)0xe0, (byte)0x97, (byte)0xfd, (byte)0x6f, (byte)0x4b, (byte)0x45, (byte)0x39, (byte)0x3e,
        (byte)0xdd, (byte)0xa3, (byte)0x4f, (byte)0xb4, (byte)0xb6, (byte)0x9a, (byte)0x0e, (byte)0x1f, (byte)0xbf,
        (byte)0x15, (byte)0xe1, (byte)0x49, (byte)0xd2, (byte)0x93, (byte)0xc6, (byte)0x92, (byte)0x72, (byte)0x9e,
        (byte)0x61, (byte)0xd1, (byte)0x63, (byte)0xfa, (byte)0xee, (byte)0xf4, (byte)0x19, (byte)0xd5, (byte)0xad,
        (byte)0x58, (byte)0xa4, (byte)0xbb, (byte)0xa1, (byte)0xdc, (byte)0xf2, (byte)0x83, (byte)0x37, (byte)0x42,
        (byte)0xe4, (byte)0x7a, (byte)0x32, (byte)0x9c, (byte)0xcc, (byte)0xab, (byte)0x4a, (byte)0x8f, (byte)0x6e,
        (byte)0x04, (byte)0x27, (byte)0x2e, (byte)0xe7, (byte)0xe2, (byte)0x5a, (byte)0x96, (byte)0x16, (byte)0x23,
        (byte)0x2b, (byte)0xc2, (byte)0x65, (byte)0x66, (byte)0x0f, (byte)0xbc, (byte)0xa9, (byte)0x47, (byte)0x41,
        (byte)0x34, (byte)0x48, (byte)0xfc, (byte)0xb7, (byte)0x6a, (byte)0x88, (byte)0xa5, (byte)0x53, (byte)0x86,
        (byte)0xf9, (byte)0x5b, (byte)0xdb, (byte)0x38, (byte)0x7b, (byte)0xc3, (byte)0x1e, (byte)0x22, (byte)0x33,
        (byte)0x24, (byte)0x28, (byte)0x36, (byte)0xc7, (byte)0xb2, (byte)0x3b, (byte)0x8e, (byte)0x77, (byte)0xba,
        (byte)0xf5, (byte)0x14, (byte)0x9f, (byte)0x08, (byte)0x55, (byte)0x9b, (byte)0x4c, (byte)0xfe, (byte)0x60,
        (byte)0x5c, (byte)0xda, (byte)0x18, (byte)0x46, (byte)0xcd, (byte)0x7d, (byte)0x21, (byte)0xb0, (byte)0x3f,
        (byte)0x1b, (byte)0x89, (byte)0xff, (byte)0xeb, (byte)0x84, (byte)0x69, (byte)0x3a, (byte)0x9d, (byte)0xd7,
        (byte)0xd3, (byte)0x70, (byte)0x67, (byte)0x40, (byte)0xb5, (byte)0xde, (byte)0x5d, (byte)0x30, (byte)0x91,
        (byte)0xb1, (byte)0x78, (byte)0x11, (byte)0x01, (byte)0xe5, (byte)0x00, (byte)0x68, (byte)0x98, (byte)0xa0,
        (byte)0xc5, (byte)0x02, (byte)0xa6, (byte)0x74, (byte)0x2d, (byte)0x0b, (byte)0xa2, (byte)0x76, (byte)0xb3,
        (byte)0xbe, (byte)0xce, (byte)0xbd, (byte)0xae, (byte)0xe9, (byte)0x8a, (byte)0x31, (byte)0x1c, (byte)0xec,
        (byte)0xf1, (byte)0x99, (byte)0x94, (byte)0xaa, (byte)0xf6, (byte)0x26, (byte)0x2f, (byte)0xef, (byte)0xe8,
        (byte)0x8c, (byte)0x35, (byte)0x03, (byte)0xd4, (byte)0x7f, (byte)0xfb, (byte)0x05, (byte)0xc1, (byte)0x5e,
        (byte)0x90, (byte)0x20, (byte)0x3d, (byte)0x82, (byte)0xf7, (byte)0xea, (byte)0x0a, (byte)0x0d, (byte)0x7e,
        (byte)0xf8, (byte)0x50, (byte)0x1a, (byte)0xc4, (byte)0x07, (byte)0x57, (byte)0xb8, (byte)0x3c, (byte)0x62,
        (byte)0xe3, (byte)0xc8, (byte)0xac, (byte)0x52, (byte)0x64, (byte)0x10, (byte)0xd0, (byte)0xd9, (byte)0x13,
        (byte)0x0c, (byte)0x12, (byte)0x29, (byte)0x51, (byte)0xb9, (byte)0xcf, (byte)0xd6, (byte)0x73, (byte)0x8d,
        (byte)0x81, (byte)0x54, (byte)0xc0, (byte)0xed, (byte)0x4e, (byte)0x44, (byte)0xa7, (byte)0x2a, (byte)0x85,
        (byte)0x25, (byte)0xe6, (byte)0xca, (byte)0x7c, (byte)0x8b, (byte)0x56, (byte)0x80 };

    private static final byte[] S1 = new byte[]{ (byte)0xce, (byte)0xbb, (byte)0xeb, (byte)0x92, (byte)0xea, (byte)0xcb,
        (byte)0x13, (byte)0xc1, (byte)0xe9, (byte)0x3a, (byte)0xd6, (byte)0xb2, (byte)0xd2, (byte)0x90, (byte)0x17,
        (byte)0xf8, (byte)0x42, (byte)0x15, (byte)0x56, (byte)0xb4, (byte)0x65, (byte)0x1c, (byte)0x88, (byte)0x43,
        (byte)0xc5, (byte)0x5c, (byte)0x36, (byte)0xba, (byte)0xf5, (byte)0x57, (byte)0x67, (byte)0x8d, (byte)0x31,
        (byte)0xf6, (byte)0x64, (byte)0x58, (byte)0x9e, (byte)0xf4, (byte)0x22, (byte)0xaa, (byte)0x75, (byte)0x0f,
        (byte)0x02, (byte)0xb1, (byte)0xdf, (byte)0x6d, (byte)0x73, (byte)0x4d, (byte)0x7c, (byte)0x26, (byte)0x2e,
        (byte)0xf7, (byte)0x08, (byte)0x5d, (byte)0x44, (byte)0x3e, (byte)0x9f, (byte)0x14, (byte)0xc8, (byte)0xae,
        (byte)0x54, (byte)0x10, (byte)0xd8, (byte)0xbc, (byte)0x1a, (byte)0x6b, (byte)0x69, (byte)0xf3, (byte)0xbd,
        (byte)0x33, (byte)0xab, (byte)0xfa, (byte)0xd1, (byte)0x9b, (byte)0x68, (byte)0x4e, (byte)0x16, (byte)0x95,
        (byte)0x91, (byte)0xee, (byte)0x4c, (byte)0x63, (byte)0x8e, (byte)0x5b, (byte)0xcc, (byte)0x3c, (byte)0x19,
        (byte)0xa1, (byte)0x81, (byte)0x49, (byte)0x7b, (byte)0xd9, (byte)0x6f, (byte)0x37, (byte)0x60, (byte)0xca,
        (byte)0xe7, (byte)0x2b, (byte)0x48, (byte)0xfd, (byte)0x96, (byte)0x45, (byte)0xfc, (byte)0x41, (byte)0x12,
        (byte)0x0d, (byte)0x79, (byte)0xe5, (byte)0x89, (byte)0x8c, (byte)0xe3, (byte)0x20, (byte)0x30, (byte)0xdc,
        (byte)0xb7, (byte)0x6c, (byte)0x4a, (byte)0xb5, (byte)0x3f, (byte)0x97, (byte)0xd4, (byte)0x62, (byte)0x2d,
        (byte)0x06, (byte)0xa4, (byte)0xa5, (byte)0x83, (byte)0x5f, (byte)0x2a, (byte)0xda, (byte)0xc9, (byte)0x00,
        (byte)0x7e, (byte)0xa2, (byte)0x55, (byte)0xbf, (byte)0x11, (byte)0xd5, (byte)0x9c, (byte)0xcf, (byte)0x0e,
        (byte)0x0a, (byte)0x3d, (byte)0x51, (byte)0x7d, (byte)0x93, (byte)0x1b, (byte)0xfe, (byte)0xc4, (byte)0x47,
        (byte)0x09, (byte)0x86, (byte)0x0b, (byte)0x8f, (byte)0x9d, (byte)0x6a, (byte)0x07, (byte)0xb9, (byte)0xb0,
        (byte)0x98, (byte)0x18, (byte)0x32, (byte)0x71, (byte)0x4b, (byte)0xef, (byte)0x3b, (byte)0x70, (byte)0xa0,
        (byte)0xe4, (byte)0x40, (byte)0xff, (byte)0xc3, (byte)0xa9, (byte)0xe6, (byte)0x78, (byte)0xf9, (byte)0x8b,
        (byte)0x46, (byte)0x80, (byte)0x1e, (byte)0x38, (byte)0xe1, (byte)0xb8, (byte)0xa8, (byte)0xe0, (byte)0x0c,
        (byte)0x23, (byte)0x76, (byte)0x1d, (byte)0x25, (byte)0x24, (byte)0x05, (byte)0xf1, (byte)0x6e, (byte)0x94,
        (byte)0x28, (byte)0x9a, (byte)0x84, (byte)0xe8, (byte)0xa3, (byte)0x4f, (byte)0x77, (byte)0xd3, (byte)0x85,
        (byte)0xe2, (byte)0x52, (byte)0xf2, (byte)0x82, (byte)0x50, (byte)0x7a, (byte)0x2f, (byte)0x74, (byte)0x53,
        (byte)0xb3, (byte)0x61, (byte)0xaf, (byte)0x39, (byte)0x35, (byte)0xde, (byte)0xcd, (byte)0x1f, (byte)0x99,
        (byte)0xac, (byte)0xad, (byte)0x72, (byte)0x2c, (byte)0xdd, (byte)0xd0, (byte)0x87, (byte)0xbe, (byte)0x5e,
        (byte)0xa6, (byte)0xec, (byte)0x04, (byte)0xc6, (byte)0x03, (byte)0x34, (byte)0xfb, (byte)0xdb, (byte)0x59,
        (byte)0xb6, (byte)0xc2, (byte)0x01, (byte)0xf0, (byte)0x5a, (byte)0xed, (byte)0xa7, (byte)0x66, (byte)0x21,
        (byte)0x7f, (byte)0x8a, (byte)0x27, (byte)0xc7, (byte)0xc0, (byte)0x29, (byte)0xd7 };

    private static final byte[] S2 = new byte[]{ (byte)0x93, (byte)0xd9, (byte)0x9a, (byte)0xb5, (byte)0x98, (byte)0x22,
        (byte)0x45, (byte)0xfc, (byte)0xba, (byte)0x6a, (byte)0xdf, (byte)0x02, (byte)0x9f, (byte)0xdc, (byte)0x51,
        (byte)0x59, (byte)0x4a, (byte)0x17, (byte)0x2b, (byte)0xc2, (byte)0x94, (byte)0xf4, (byte)0xbb, (byte)0xa3,
        (byte)0x62, (byte)0xe4, (byte)0x71, (byte)0xd4, (byte)0xcd, (byte)0x70, (byte)0x16, (byte)0xe1, (byte)0x49,
        (byte)0x3c, (byte)0xc0, (byte)0xd8, (byte)0x5c, (byte)0x9b, (byte)0xad, (byte)0x85, (byte)0x53, (byte)0xa1,
        (byte)0x7a, (byte)0xc8, (byte)0x2d, (byte)0xe0, (byte)0xd1, (byte)0x72, (byte)0xa6, (byte)0x2c, (byte)0xc4,
        (byte)0xe3, (byte)0x76, (byte)0x78, (byte)0xb7, (byte)0xb4, (byte)0x09, (byte)0x3b, (byte)0x0e, (byte)0x41,
        (byte)0x4c, (byte)0xde, (byte)0xb2, (byte)0x90, (byte)0x25, (byte)0xa5, (byte)0xd7, (byte)0x03, (byte)0x11,
        (byte)0x00, (byte)0xc3, (byte)0x2e, (byte)0x92, (byte)0xef, (byte)0x4e, (byte)0x12, (byte)0x9d, (byte)0x7d,
        (byte)0xcb, (byte)0x35, (byte)0x10, (byte)0xd5, (byte)0x4f, (byte)0x9e, (byte)0x4d, (byte)0xa9, (byte)0x55,
        (byte)0xc6, (byte)0xd0, (byte)0x7b, (byte)0x18, (byte)0x97, (byte)0xd3, (byte)0x36, (byte)0xe6, (byte)0x48,
        (byte)0x56, (byte)0x81, (byte)0x8f, (byte)0x77, (byte)0xcc, (byte)0x9c, (byte)0xb9, (byte)0xe2, (byte)0xac,
        (byte)0xb8, (byte)0x2f, (byte)0x15, (byte)0xa4, (byte)0x7c, (byte)0xda, (byte)0x38, (byte)0x1e, (byte)0x0b,
        (byte)0x05, (byte)0xd6, (byte)0x14, (byte)0x6e, (byte)0x6c, (byte)0x7e, (byte)0x66, (byte)0xfd, (byte)0xb1,
        (byte)0xe5, (byte)0x60, (byte)0xaf, (byte)0x5e, (byte)0x33, (byte)0x87, (byte)0xc9, (byte)0xf0, (byte)0x5d,
        (byte)0x6d, (byte)0x3f, (byte)0x88, (byte)0x8d, (byte)0xc7, (byte)0xf7, (byte)0x1d, (byte)0xe9, (byte)0xec,
        (byte)0xed, (byte)0x80, (byte)0x29, (byte)0x27, (byte)0xcf, (byte)0x99, (byte)0xa8, (byte)0x50, (byte)0x0f,
        (byte)0x37, (byte)0x24, (byte)0x28, (byte)0x30, (byte)0x95, (byte)0xd2, (byte)0x3e, (byte)0x5b, (byte)0x40,
        (byte)0x83, (byte)0xb3, (byte)0x69, (byte)0x57, (byte)0x1f, (byte)0x07, (byte)0x1c, (byte)0x8a, (byte)0xbc,
        (byte)0x20, (byte)0xeb, (byte)0xce, (byte)0x8e, (byte)0xab, (byte)0xee, (byte)0x31, (byte)0xa2, (byte)0x73,
        (byte)0xf9, (byte)0xca, (byte)0x3a, (byte)0x1a, (byte)0xfb, (byte)0x0d, (byte)0xc1, (byte)0xfe, (byte)0xfa,
        (byte)0xf2, (byte)0x6f, (byte)0xbd, (byte)0x96, (byte)0xdd, (byte)0x43, (byte)0x52, (byte)0xb6, (byte)0x08,
        (byte)0xf3, (byte)0xae, (byte)0xbe, (byte)0x19, (byte)0x89, (byte)0x32, (byte)0x26, (byte)0xb0, (byte)0xea,
        (byte)0x4b, (byte)0x64, (byte)0x84, (byte)0x82, (byte)0x6b, (byte)0xf5, (byte)0x79, (byte)0xbf, (byte)0x01,
        (byte)0x5f, (byte)0x75, (byte)0x63, (byte)0x1b, (byte)0x23, (byte)0x3d, (byte)0x68, (byte)0x2a, (byte)0x65,
        (byte)0xe8, (byte)0x91, (byte)0xf6, (byte)0xff, (byte)0x13, (byte)0x58, (byte)0xf1, (byte)0x47, (byte)0x0a,
        (byte)0x7f, (byte)0xc5, (byte)0xa7, (byte)0xe7, (byte)0x61, (byte)0x5a, (byte)0x06, (byte)0x46, (byte)0x44,
        (byte)0x42, (byte)0x04, (byte)0xa0, (byte)0xdb, (byte)0x39, (byte)0x86, (byte)0x54, (byte)0xaa, (byte)0x8c,
        (byte)0x34, (byte)0x21, (byte)0x8b, (byte)0xf8, (byte)0x0c, (byte)0x74, (byte)0x67 };

    private static final byte[] S3 = new byte[]{ (byte)0x68, (byte)0x8d, (byte)0xca, (byte)0x4d, (byte)0x73, (byte)0x4b,
        (byte)0x4e, (byte)0x2a, (byte)0xd4, (byte)0x52, (byte)0x26, (byte)0xb3, (byte)0x54, (byte)0x1e, (byte)0x19,
        (byte)0x1f, (byte)0x22, (byte)0x03, (byte)0x46, (byte)0x3d, (byte)0x2d, (byte)0x4a, (byte)0x53, (byte)0x83,
        (byte)0x13, (byte)0x8a, (byte)0xb7, (byte)0xd5, (byte)0x25, (byte)0x79, (byte)0xf5, (byte)0xbd, (byte)0x58,
        (byte)0x2f, (byte)0x0d, (byte)0x02, (byte)0xed, (byte)0x51, (byte)0x9e, (byte)0x11, (byte)0xf2, (byte)0x3e,
        (byte)0x55, (byte)0x5e, (byte)0xd1, (byte)0x16, (byte)0x3c, (byte)0x66, (byte)0x70, (byte)0x5d, (byte)0xf3,
        (byte)0x45, (byte)0x40, (byte)0xcc, (byte)0xe8, (byte)0x94, (byte)0x56, (byte)0x08, (byte)0xce, (byte)0x1a,
        (byte)0x3a, (byte)0xd2, (byte)0xe1, (byte)0xdf, (byte)0xb5, (byte)0x38, (byte)0x6e, (byte)0x0e, (byte)0xe5,
        (byte)0xf4, (byte)0xf9, (byte)0x86, (byte)0xe9, (byte)0x4f, (byte)0xd6, (byte)0x85, (byte)0x23, (byte)0xcf,
        (byte)0x32, (byte)0x99, (byte)0x31, (byte)0x14, (byte)0xae, (byte)0xee, (byte)0xc8, (byte)0x48, (byte)0xd3,
        (byte)0x30, (byte)0xa1, (byte)0x92, (byte)0x41, (byte)0xb1, (byte)0x18, (byte)0xc4, (byte)0x2c, (byte)0x71,
        (byte)0x72, (byte)0x44, (byte)0x15, (byte)0xfd, (byte)0x37, (byte)0xbe, (byte)0x5f, (byte)0xaa, (byte)0x9b,
        (byte)0x88, (byte)0xd8, (byte)0xab, (byte)0x89, (byte)0x9c, (byte)0xfa, (byte)0x60, (byte)0xea, (byte)0xbc,
        (byte)0x62, (byte)0x0c, (byte)0x24, (byte)0xa6, (byte)0xa8, (byte)0xec, (byte)0x67, (byte)0x20, (byte)0xdb,
        (byte)0x7c, (byte)0x28, (byte)0xdd, (byte)0xac, (byte)0x5b, (byte)0x34, (byte)0x7e, (byte)0x10, (byte)0xf1,
        (byte)0x7b, (byte)0x8f, (byte)0x63, (byte)0xa0, (byte)0x05, (byte)0x9a, (byte)0x43, (byte)0x77, (byte)0x21,
        (byte)0xbf, (byte)0x27, (byte)0x09, (byte)0xc3, (byte)0x9f, (byte)0xb6, (byte)0xd7, (byte)0x29, (byte)0xc2,
        (byte)0xeb, (byte)0xc0, (byte)0xa4, (byte)0x8b, (byte)0x8c, (byte)0x1d, (byte)0xfb, (byte)0xff, (byte)0xc1,
        (byte)0xb2, (byte)0x97, (byte)0x2e, (byte)0xf8, (byte)0x65, (byte)0xf6, (byte)0x75, (byte)0x07, (byte)0x04,
        (byte)0x49, (byte)0x33, (byte)0xe4, (byte)0xd9, (byte)0xb9, (byte)0xd0, (byte)0x42, (byte)0xc7, (byte)0x6c,
        (byte)0x90, (byte)0x00, (byte)0x8e, (byte)0x6f, (byte)0x50, (byte)0x01, (byte)0xc5, (byte)0xda, (byte)0x47,
        (byte)0x3f, (byte)0xcd, (byte)0x69, (byte)0xa2, (byte)0xe2, (byte)0x7a, (byte)0xa7, (byte)0xc6, (byte)0x93,
        (byte)0x0f, (byte)0x0a, (byte)0x06, (byte)0xe6, (byte)0x2b, (byte)0x96, (byte)0xa3, (byte)0x1c, (byte)0xaf,
        (byte)0x6a, (byte)0x12, (byte)0x84, (byte)0x39, (byte)0xe7, (byte)0xb0, (byte)0x82, (byte)0xf7, (byte)0xfe,
        (byte)0x9d, (byte)0x87, (byte)0x5c, (byte)0x81, (byte)0x35, (byte)0xde, (byte)0xb4, (byte)0xa5, (byte)0xfc,
        (byte)0x80, (byte)0xef, (byte)0xcb, (byte)0xbb, (byte)0x6b, (byte)0x76, (byte)0xba, (byte)0x5a, (byte)0x7d,
        (byte)0x78, (byte)0x0b, (byte)0x95, (byte)0xe3, (byte)0xad, (byte)0x74, (byte)0x98, (byte)0x3b, (byte)0x36,
        (byte)0x64, (byte)0x6d, (byte)0xdc, (byte)0xf0, (byte)0x59, (byte)0xa9, (byte)0x4c, (byte)0x17, (byte)0x7f,
        (byte)0x91, (byte)0xb8, (byte)0xc9, (byte)0x57, (byte)0x1b, (byte)0xe0, (byte)0x61 };

    public Memoable copy()
    {
        return new DSTU7564Digest(this);
    }

    public void reset(Memoable other)
    {
        DSTU7564Digest d = (DSTU7564Digest)other;

        copyIn(d);
    }
}
