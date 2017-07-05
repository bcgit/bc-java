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
    private static final int REDUCTIONAL_POLYNOMIAL = 0x011d;
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

    private byte[] padded;
    private byte[][] state;

    private byte[][] tempState1;
    private byte[][] tempState2;

    private byte[] tempBuffer;
    private byte[] mixColumnsResult;

    private long[] tempLongBuffer;

    private long inputLength;
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

        this.padded = Arrays.clone(digest.padded);
        this.state = Arrays.clone(digest.state);

        this.tempState1 = Arrays.clone(digest.tempState1);
        this.tempState2 = Arrays.clone(digest.tempState2);

        this.tempBuffer = Arrays.clone(digest.tempBuffer);
        this.mixColumnsResult = Arrays.clone(digest.mixColumnsResult);

        this.tempLongBuffer = Arrays.clone(digest.tempLongBuffer);

        this.inputLength = digest.inputLength;
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
        this.padded = null;

        this.tempState1 = new byte[STATE_BYTES_SIZE_1024][];
        this.tempState2 = new byte[STATE_BYTES_SIZE_1024][];

        for (int bufferIndex = 0; bufferIndex < state.length; bufferIndex++)
        {
            this.tempState1[bufferIndex] = new byte[ROWS];
            this.tempState2[bufferIndex] = new byte[ROWS];
        }

        this.tempBuffer = new byte[NB_1024];
        this.mixColumnsResult = new byte[ROWS];
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
        }
        inputLength++;
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
                inputLength += blockSize;
                len -= blockSize;
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
        padded = pad(buf, 0, bufOff);

        int paddedLen = padded.length;
        int paddedOff = 0;

        while (paddedLen != 0)
        {
            processBlock(padded, paddedOff);
            paddedOff += blockSize;
            paddedLen -= blockSize;
        }

        byte[][] temp = new byte[STATE_BYTES_SIZE_1024][];

        for (int bufferIndex = 0; bufferIndex < state.length; bufferIndex++)
        {

            temp[bufferIndex] = new byte[ROWS];

//            System.out.println(state.length);
//            System.out.println(temp.length);
//            System.out.println(state[bufferIndex].length);
//            System.out.println(temp[bufferIndex].length);


            System.arraycopy(state[bufferIndex], 0, temp[bufferIndex], 0, ROWS);
        }

        for (int roundIndex = 0; roundIndex < rounds; roundIndex++)
        {

            /* AddRoundConstants */
            for (int columnIndex = 0; columnIndex < columns; columnIndex++)
            {
                temp[columnIndex][0] ^= (byte)((columnIndex * 0x10) ^ roundIndex); // Defined in standard
            }

            /* SubBytes */
            for (int rowIndex = 0; rowIndex < ROWS; rowIndex++)
            {
                for (int columnIndex = 0; columnIndex < columns; columnIndex++)
                {
                    temp[columnIndex][rowIndex] = sBoxes[rowIndex % 4][temp[columnIndex][rowIndex] & 0xFF];
                }
            }
            /* ShiftBytes */
            int shift = -1;
            for (int rowIndex = 0; rowIndex < ROWS; rowIndex++)
            {
                if ((rowIndex == ROWS - 1) && (columns == NB_1024))
                {
                    shift = 11; // Defined in standard
                }
                else
                {
                    shift++;
                }

                for (int columnIndex = 0; columnIndex < columns; columnIndex++)
                {
                    tempBuffer[(columnIndex + shift) % columns] = temp[columnIndex][rowIndex];
                }
                for (int columnIndex = 0; columnIndex < columns; columnIndex++)
                {
                    temp[columnIndex][rowIndex] = tempBuffer[columnIndex];
                }
            }

            /* MixColumns */
            byte multiplicationResult;

            for (int columnIndex = 0; columnIndex < columns; columnIndex++)
            {

                Arrays.fill(mixColumnsResult, (byte)0);
                for (int rowIndex = ROWS - 1; rowIndex >= 0; rowIndex--)
                {

                    multiplicationResult = 0;
                    for (int rowInternalIndex = ROWS - 1; rowInternalIndex >= 0; rowInternalIndex--)
                    {
                        multiplicationResult ^= multiplyGF(temp[columnIndex][rowInternalIndex], mds_matrix[rowIndex][rowInternalIndex]);
                    }

                    mixColumnsResult[rowIndex] = multiplicationResult;
                }
                for (int rowIndex = 0; rowIndex < ROWS; rowIndex++)
                {
                    temp[columnIndex][rowIndex] = mixColumnsResult[rowIndex];
                }
            }
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

        inputLength = 0;
        bufOff = 0;
        
        Arrays.fill(buf, (byte)0);

        if (padded != null)
        {
            Arrays.fill(padded, (byte)0);
        }
    }

    private void processBlock(byte[] input, int inOff)
    {
        for (int bufferIndex = 0; bufferIndex < state.length; bufferIndex++)
        {
            Arrays.fill(tempState1[bufferIndex], (byte)0);
            Arrays.fill(tempState2[bufferIndex], (byte)0);
        }

        for (int bufferIndex = 0; bufferIndex < ROWS; bufferIndex++)
        {
            for (int byteIndex = 0; byteIndex < columns; byteIndex++)
            {
                tempState1[byteIndex][bufferIndex] = (byte)(state[byteIndex][bufferIndex] ^ input[byteIndex * ROWS + bufferIndex + inOff]);
                tempState2[byteIndex][bufferIndex] = input[byteIndex * ROWS + bufferIndex + inOff];
            }
        }

        P(); // mixing tempState1
        Q(); // mixing tempState2

        for (int bufferIndex = 0; bufferIndex < ROWS; bufferIndex++)
        {
            for (int byteIndex = 0; byteIndex < columns; byteIndex++)
            {
                state[byteIndex][bufferIndex] ^= (byte)(tempState1[byteIndex][bufferIndex] ^ tempState2[byteIndex][bufferIndex]);
            }
        }
    }

    private void Q()
    {
        for (int roundIndex = 0; roundIndex < rounds; roundIndex++)
        {

            /* AddRoundConstantsQ */
            for (int columnIndex = 0; columnIndex < columns; columnIndex++)
            {
                tempLongBuffer[columnIndex] = Pack.littleEndianToLong(tempState2[columnIndex], 0);

                tempLongBuffer[columnIndex] += (0x00F0F0F0F0F0F0F3L ^ ((((long)(columns - columnIndex - 1) * 0x10L) ^ (long)roundIndex) << (7 * 8))); // Defined in standard

                Pack.longToLittleEndian(tempLongBuffer[columnIndex], tempState2[columnIndex], 0);
            }

            /* SubBytes */
            for (int rowIndex = 0; rowIndex < ROWS; rowIndex++)
            {
                for (int columnIndex = 0; columnIndex < columns; columnIndex++)
                {
                    tempState2[columnIndex][rowIndex] = sBoxes[rowIndex % 4][tempState2[columnIndex][rowIndex] & 0xFF];
                }
            }

            /* ShiftBytes */
            int shift = -1;
            for (int rowIndex = 0; rowIndex < ROWS; rowIndex++)
            {
                if ((rowIndex == ROWS - 1) && (columns == NB_1024))
                {
                    shift = 11; // Defined in standard
                }
                else
                {
                    shift++;
                }

                for (int columnIndex = 0; columnIndex < columns; columnIndex++)
                {
                    tempBuffer[(columnIndex + shift) % columns] = tempState2[columnIndex][rowIndex];
                }
                for (int columnIndex = 0; columnIndex < columns; columnIndex++)
                {
                    tempState2[columnIndex][rowIndex] = tempBuffer[columnIndex];
                }
            }

            /* MixColumns */
            byte multiplicationResult;

            for (int columnIndex = 0; columnIndex < columns; columnIndex++)
            {

                Arrays.fill(mixColumnsResult, (byte)0);
                for (int rowIndex = ROWS - 1; rowIndex >= 0; rowIndex--)
                {

                    multiplicationResult = 0;
                    for (int rowInternalIndex = ROWS - 1; rowInternalIndex >= 0; rowInternalIndex--)
                    {
                        multiplicationResult ^= multiplyGF(tempState2[columnIndex][rowInternalIndex], mds_matrix[rowIndex][rowInternalIndex]);
                    }

                    mixColumnsResult[rowIndex] = multiplicationResult;
                }
                for (int rowIndex = 0; rowIndex < ROWS; rowIndex++)
                {
                    tempState2[columnIndex][rowIndex] = mixColumnsResult[rowIndex];
                }
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
                //System.out.println((byte)((columnIndex * 0x10) ^ roundIndex));
                tempState1[columnIndex][0] ^= (byte)((columnIndex * 0x10) ^ roundIndex); // Defined in standard
            }

            /* SubBytes */
            for (int rowIndex = 0; rowIndex < ROWS; rowIndex++)
            {
                for (int columnIndex = 0; columnIndex < columns; columnIndex++)
                {
                    tempState1[columnIndex][rowIndex] = sBoxes[rowIndex % 4][tempState1[columnIndex][rowIndex] & 0xFF];
                }
            }
            /* ShiftBytes */
            int shift = -1;
            for (int rowIndex = 0; rowIndex < ROWS; rowIndex++)
            {
                if ((rowIndex == ROWS - 1) && (columns == NB_1024))
                {
                    shift = 11; // Defined in standard
                }
                else
                {
                    shift++;
                }

                for (int columnIndex = 0; columnIndex < columns; columnIndex++)
                {
                    tempBuffer[(columnIndex + shift) % columns] = tempState1[columnIndex][rowIndex];
                }
                for (int columnIndex = 0; columnIndex < columns; columnIndex++)
                {
                    tempState1[columnIndex][rowIndex] = tempBuffer[columnIndex];
                }
            }

            /* MixColumns */
            byte multiplicationResult;

            for (int columnIndex = 0; columnIndex < columns; columnIndex++)
            {

                Arrays.fill(mixColumnsResult, (byte)0);
                for (int rowIndex = ROWS - 1; rowIndex >= 0; rowIndex--)
                {

                    multiplicationResult = 0;
                    for (int rowInternalIndex = ROWS - 1; rowInternalIndex >= 0; rowInternalIndex--)
                    {
                        multiplicationResult ^= multiplyGF(tempState1[columnIndex][rowInternalIndex], mds_matrix[rowIndex][rowInternalIndex]);
                    }

                    mixColumnsResult[rowIndex] = multiplicationResult;
                }
                for (int rowIndex = 0; rowIndex < ROWS; rowIndex++)
                {
                    tempState1[columnIndex][rowIndex] = mixColumnsResult[rowIndex];
                }
            }
        }
    }

    private byte multiplyGF(byte x, byte y)
    {

        byte result = 0;
        byte highestBit;
        for (int bitIndex = 0; bitIndex < BITS_IN_BYTE; bitIndex++)
        {
            if ((y & (byte)0x01) == 1)
            {
                result ^= x;
            }

            highestBit = (byte)(x & (byte)0x80);

            x <<= 1;

            if (highestBit == (byte)0x80)
            {
                x = (byte)((int)x ^ REDUCTIONAL_POLYNOMIAL);
            }

            y >>= 1;
        }
        return result;
    }

    private byte[] pad(byte[] in, int inOff, int len)
    {
        byte[] padded;
        if (blockSize - len < 13)         // terminator byte + 96 bits of length
        {
            padded = new byte[2 * blockSize];
        }
        else
        {
            padded = new byte[blockSize];
        }

        System.arraycopy(in, inOff, padded, 0, len);

        padded[len] = (byte)0x80; // Defined in standard;
        // Defined in standard;
        Pack.longToLittleEndian(inputLength * BITS_IN_BYTE, padded, padded.length - 12);

        return padded;
    }

    //region CONSTANTS
    private static final byte[][] mds_matrix = new byte[][]{
        new byte[]{0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04},
        new byte[]{0x04, 0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07},
        new byte[]{0x07, 0x04, 0x01, 0x01, 0x05, 0x01, 0x08, 0x06},
        new byte[]{0x06, 0x07, 0x04, 0x01, 0x01, 0x05, 0x01, 0x08},
        new byte[]{0x08, 0x06, 0x07, 0x04, 0x01, 0x01, 0x05, 0x01},
        new byte[]{0x01, 0x08, 0x06, 0x07, 0x04, 0x01, 0x01, 0x05},
        new byte[]{0x05, 0x01, 0x08, 0x06, 0x07, 0x04, 0x01, 0x01},
        new byte[]{0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04, 0x01}
    };

    private static final byte[][] sBoxes = new byte[][]{
        new byte[]{
            (byte)0xa8, (byte)0x43, (byte)0x5f, (byte)0x06, (byte)0x6b, (byte)0x75, (byte)0x6c, (byte)0x59, (byte)0x71, (byte)0xdf, (byte)0x87, (byte)0x95, (byte)0x17, (byte)0xf0, (byte)0xd8, (byte)0x09,
            (byte)0x6d, (byte)0xf3, (byte)0x1d, (byte)0xcb, (byte)0xc9, (byte)0x4d, (byte)0x2c, (byte)0xaf, (byte)0x79, (byte)0xe0, (byte)0x97, (byte)0xfd, (byte)0x6f, (byte)0x4b, (byte)0x45, (byte)0x39,
            (byte)0x3e, (byte)0xdd, (byte)0xa3, (byte)0x4f, (byte)0xb4, (byte)0xb6, (byte)0x9a, (byte)0x0e, (byte)0x1f, (byte)0xbf, (byte)0x15, (byte)0xe1, (byte)0x49, (byte)0xd2, (byte)0x93, (byte)0xc6,
            (byte)0x92, (byte)0x72, (byte)0x9e, (byte)0x61, (byte)0xd1, (byte)0x63, (byte)0xfa, (byte)0xee, (byte)0xf4, (byte)0x19, (byte)0xd5, (byte)0xad, (byte)0x58, (byte)0xa4, (byte)0xbb, (byte)0xa1,
            (byte)0xdc, (byte)0xf2, (byte)0x83, (byte)0x37, (byte)0x42, (byte)0xe4, (byte)0x7a, (byte)0x32, (byte)0x9c, (byte)0xcc, (byte)0xab, (byte)0x4a, (byte)0x8f, (byte)0x6e, (byte)0x04, (byte)0x27,
            (byte)0x2e, (byte)0xe7, (byte)0xe2, (byte)0x5a, (byte)0x96, (byte)0x16, (byte)0x23, (byte)0x2b, (byte)0xc2, (byte)0x65, (byte)0x66, (byte)0x0f, (byte)0xbc, (byte)0xa9, (byte)0x47, (byte)0x41,
            (byte)0x34, (byte)0x48, (byte)0xfc, (byte)0xb7, (byte)0x6a, (byte)0x88, (byte)0xa5, (byte)0x53, (byte)0x86, (byte)0xf9, (byte)0x5b, (byte)0xdb, (byte)0x38, (byte)0x7b, (byte)0xc3, (byte)0x1e,
            (byte)0x22, (byte)0x33, (byte)0x24, (byte)0x28, (byte)0x36, (byte)0xc7, (byte)0xb2, (byte)0x3b, (byte)0x8e, (byte)0x77, (byte)0xba, (byte)0xf5, (byte)0x14, (byte)0x9f, (byte)0x08, (byte)0x55,
            (byte)0x9b, (byte)0x4c, (byte)0xfe, (byte)0x60, (byte)0x5c, (byte)0xda, (byte)0x18, (byte)0x46, (byte)0xcd, (byte)0x7d, (byte)0x21, (byte)0xb0, (byte)0x3f, (byte)0x1b, (byte)0x89, (byte)0xff,
            (byte)0xeb, (byte)0x84, (byte)0x69, (byte)0x3a, (byte)0x9d, (byte)0xd7, (byte)0xd3, (byte)0x70, (byte)0x67, (byte)0x40, (byte)0xb5, (byte)0xde, (byte)0x5d, (byte)0x30, (byte)0x91, (byte)0xb1,
            (byte)0x78, (byte)0x11, (byte)0x01, (byte)0xe5, (byte)0x00, (byte)0x68, (byte)0x98, (byte)0xa0, (byte)0xc5, (byte)0x02, (byte)0xa6, (byte)0x74, (byte)0x2d, (byte)0x0b, (byte)0xa2, (byte)0x76,
            (byte)0xb3, (byte)0xbe, (byte)0xce, (byte)0xbd, (byte)0xae, (byte)0xe9, (byte)0x8a, (byte)0x31, (byte)0x1c, (byte)0xec, (byte)0xf1, (byte)0x99, (byte)0x94, (byte)0xaa, (byte)0xf6, (byte)0x26,
            (byte)0x2f, (byte)0xef, (byte)0xe8, (byte)0x8c, (byte)0x35, (byte)0x03, (byte)0xd4, (byte)0x7f, (byte)0xfb, (byte)0x05, (byte)0xc1, (byte)0x5e, (byte)0x90, (byte)0x20, (byte)0x3d, (byte)0x82,
            (byte)0xf7, (byte)0xea, (byte)0x0a, (byte)0x0d, (byte)0x7e, (byte)0xf8, (byte)0x50, (byte)0x1a, (byte)0xc4, (byte)0x07, (byte)0x57, (byte)0xb8, (byte)0x3c, (byte)0x62, (byte)0xe3, (byte)0xc8,
            (byte)0xac, (byte)0x52, (byte)0x64, (byte)0x10, (byte)0xd0, (byte)0xd9, (byte)0x13, (byte)0x0c, (byte)0x12, (byte)0x29, (byte)0x51, (byte)0xb9, (byte)0xcf, (byte)0xd6, (byte)0x73, (byte)0x8d,
            (byte)0x81, (byte)0x54, (byte)0xc0, (byte)0xed, (byte)0x4e, (byte)0x44, (byte)0xa7, (byte)0x2a, (byte)0x85, (byte)0x25, (byte)0xe6, (byte)0xca, (byte)0x7c, (byte)0x8b, (byte)0x56, (byte)0x80
        },
        new byte[]{
            (byte)0xce, (byte)0xbb, (byte)0xeb, (byte)0x92, (byte)0xea, (byte)0xcb, (byte)0x13, (byte)0xc1, (byte)0xe9, (byte)0x3a, (byte)0xd6, (byte)0xb2, (byte)0xd2, (byte)0x90, (byte)0x17, (byte)0xf8,
            (byte)0x42, (byte)0x15, (byte)0x56, (byte)0xb4, (byte)0x65, (byte)0x1c, (byte)0x88, (byte)0x43, (byte)0xc5, (byte)0x5c, (byte)0x36, (byte)0xba, (byte)0xf5, (byte)0x57, (byte)0x67, (byte)0x8d,
            (byte)0x31, (byte)0xf6, (byte)0x64, (byte)0x58, (byte)0x9e, (byte)0xf4, (byte)0x22, (byte)0xaa, (byte)0x75, (byte)0x0f, (byte)0x02, (byte)0xb1, (byte)0xdf, (byte)0x6d, (byte)0x73, (byte)0x4d,
            (byte)0x7c, (byte)0x26, (byte)0x2e, (byte)0xf7, (byte)0x08, (byte)0x5d, (byte)0x44, (byte)0x3e, (byte)0x9f, (byte)0x14, (byte)0xc8, (byte)0xae, (byte)0x54, (byte)0x10, (byte)0xd8, (byte)0xbc,
            (byte)0x1a, (byte)0x6b, (byte)0x69, (byte)0xf3, (byte)0xbd, (byte)0x33, (byte)0xab, (byte)0xfa, (byte)0xd1, (byte)0x9b, (byte)0x68, (byte)0x4e, (byte)0x16, (byte)0x95, (byte)0x91, (byte)0xee,
            (byte)0x4c, (byte)0x63, (byte)0x8e, (byte)0x5b, (byte)0xcc, (byte)0x3c, (byte)0x19, (byte)0xa1, (byte)0x81, (byte)0x49, (byte)0x7b, (byte)0xd9, (byte)0x6f, (byte)0x37, (byte)0x60, (byte)0xca,
            (byte)0xe7, (byte)0x2b, (byte)0x48, (byte)0xfd, (byte)0x96, (byte)0x45, (byte)0xfc, (byte)0x41, (byte)0x12, (byte)0x0d, (byte)0x79, (byte)0xe5, (byte)0x89, (byte)0x8c, (byte)0xe3, (byte)0x20,
            (byte)0x30, (byte)0xdc, (byte)0xb7, (byte)0x6c, (byte)0x4a, (byte)0xb5, (byte)0x3f, (byte)0x97, (byte)0xd4, (byte)0x62, (byte)0x2d, (byte)0x06, (byte)0xa4, (byte)0xa5, (byte)0x83, (byte)0x5f,
            (byte)0x2a, (byte)0xda, (byte)0xc9, (byte)0x00, (byte)0x7e, (byte)0xa2, (byte)0x55, (byte)0xbf, (byte)0x11, (byte)0xd5, (byte)0x9c, (byte)0xcf, (byte)0x0e, (byte)0x0a, (byte)0x3d, (byte)0x51,
            (byte)0x7d, (byte)0x93, (byte)0x1b, (byte)0xfe, (byte)0xc4, (byte)0x47, (byte)0x09, (byte)0x86, (byte)0x0b, (byte)0x8f, (byte)0x9d, (byte)0x6a, (byte)0x07, (byte)0xb9, (byte)0xb0, (byte)0x98,
            (byte)0x18, (byte)0x32, (byte)0x71, (byte)0x4b, (byte)0xef, (byte)0x3b, (byte)0x70, (byte)0xa0, (byte)0xe4, (byte)0x40, (byte)0xff, (byte)0xc3, (byte)0xa9, (byte)0xe6, (byte)0x78, (byte)0xf9,
            (byte)0x8b, (byte)0x46, (byte)0x80, (byte)0x1e, (byte)0x38, (byte)0xe1, (byte)0xb8, (byte)0xa8, (byte)0xe0, (byte)0x0c, (byte)0x23, (byte)0x76, (byte)0x1d, (byte)0x25, (byte)0x24, (byte)0x05,
            (byte)0xf1, (byte)0x6e, (byte)0x94, (byte)0x28, (byte)0x9a, (byte)0x84, (byte)0xe8, (byte)0xa3, (byte)0x4f, (byte)0x77, (byte)0xd3, (byte)0x85, (byte)0xe2, (byte)0x52, (byte)0xf2, (byte)0x82,
            (byte)0x50, (byte)0x7a, (byte)0x2f, (byte)0x74, (byte)0x53, (byte)0xb3, (byte)0x61, (byte)0xaf, (byte)0x39, (byte)0x35, (byte)0xde, (byte)0xcd, (byte)0x1f, (byte)0x99, (byte)0xac, (byte)0xad,
            (byte)0x72, (byte)0x2c, (byte)0xdd, (byte)0xd0, (byte)0x87, (byte)0xbe, (byte)0x5e, (byte)0xa6, (byte)0xec, (byte)0x04, (byte)0xc6, (byte)0x03, (byte)0x34, (byte)0xfb, (byte)0xdb, (byte)0x59,
            (byte)0xb6, (byte)0xc2, (byte)0x01, (byte)0xf0, (byte)0x5a, (byte)0xed, (byte)0xa7, (byte)0x66, (byte)0x21, (byte)0x7f, (byte)0x8a, (byte)0x27, (byte)0xc7, (byte)0xc0, (byte)0x29, (byte)0xd7
        },
        new byte[]{
            (byte)0x93, (byte)0xd9, (byte)0x9a, (byte)0xb5, (byte)0x98, (byte)0x22, (byte)0x45, (byte)0xfc, (byte)0xba, (byte)0x6a, (byte)0xdf, (byte)0x02, (byte)0x9f, (byte)0xdc, (byte)0x51, (byte)0x59,
            (byte)0x4a, (byte)0x17, (byte)0x2b, (byte)0xc2, (byte)0x94, (byte)0xf4, (byte)0xbb, (byte)0xa3, (byte)0x62, (byte)0xe4, (byte)0x71, (byte)0xd4, (byte)0xcd, (byte)0x70, (byte)0x16, (byte)0xe1,
            (byte)0x49, (byte)0x3c, (byte)0xc0, (byte)0xd8, (byte)0x5c, (byte)0x9b, (byte)0xad, (byte)0x85, (byte)0x53, (byte)0xa1, (byte)0x7a, (byte)0xc8, (byte)0x2d, (byte)0xe0, (byte)0xd1, (byte)0x72,
            (byte)0xa6, (byte)0x2c, (byte)0xc4, (byte)0xe3, (byte)0x76, (byte)0x78, (byte)0xb7, (byte)0xb4, (byte)0x09, (byte)0x3b, (byte)0x0e, (byte)0x41, (byte)0x4c, (byte)0xde, (byte)0xb2, (byte)0x90,
            (byte)0x25, (byte)0xa5, (byte)0xd7, (byte)0x03, (byte)0x11, (byte)0x00, (byte)0xc3, (byte)0x2e, (byte)0x92, (byte)0xef, (byte)0x4e, (byte)0x12, (byte)0x9d, (byte)0x7d, (byte)0xcb, (byte)0x35,
            (byte)0x10, (byte)0xd5, (byte)0x4f, (byte)0x9e, (byte)0x4d, (byte)0xa9, (byte)0x55, (byte)0xc6, (byte)0xd0, (byte)0x7b, (byte)0x18, (byte)0x97, (byte)0xd3, (byte)0x36, (byte)0xe6, (byte)0x48,
            (byte)0x56, (byte)0x81, (byte)0x8f, (byte)0x77, (byte)0xcc, (byte)0x9c, (byte)0xb9, (byte)0xe2, (byte)0xac, (byte)0xb8, (byte)0x2f, (byte)0x15, (byte)0xa4, (byte)0x7c, (byte)0xda, (byte)0x38,
            (byte)0x1e, (byte)0x0b, (byte)0x05, (byte)0xd6, (byte)0x14, (byte)0x6e, (byte)0x6c, (byte)0x7e, (byte)0x66, (byte)0xfd, (byte)0xb1, (byte)0xe5, (byte)0x60, (byte)0xaf, (byte)0x5e, (byte)0x33,
            (byte)0x87, (byte)0xc9, (byte)0xf0, (byte)0x5d, (byte)0x6d, (byte)0x3f, (byte)0x88, (byte)0x8d, (byte)0xc7, (byte)0xf7, (byte)0x1d, (byte)0xe9, (byte)0xec, (byte)0xed, (byte)0x80, (byte)0x29,
            (byte)0x27, (byte)0xcf, (byte)0x99, (byte)0xa8, (byte)0x50, (byte)0x0f, (byte)0x37, (byte)0x24, (byte)0x28, (byte)0x30, (byte)0x95, (byte)0xd2, (byte)0x3e, (byte)0x5b, (byte)0x40, (byte)0x83,
            (byte)0xb3, (byte)0x69, (byte)0x57, (byte)0x1f, (byte)0x07, (byte)0x1c, (byte)0x8a, (byte)0xbc, (byte)0x20, (byte)0xeb, (byte)0xce, (byte)0x8e, (byte)0xab, (byte)0xee, (byte)0x31, (byte)0xa2,
            (byte)0x73, (byte)0xf9, (byte)0xca, (byte)0x3a, (byte)0x1a, (byte)0xfb, (byte)0x0d, (byte)0xc1, (byte)0xfe, (byte)0xfa, (byte)0xf2, (byte)0x6f, (byte)0xbd, (byte)0x96, (byte)0xdd, (byte)0x43,
            (byte)0x52, (byte)0xb6, (byte)0x08, (byte)0xf3, (byte)0xae, (byte)0xbe, (byte)0x19, (byte)0x89, (byte)0x32, (byte)0x26, (byte)0xb0, (byte)0xea, (byte)0x4b, (byte)0x64, (byte)0x84, (byte)0x82,
            (byte)0x6b, (byte)0xf5, (byte)0x79, (byte)0xbf, (byte)0x01, (byte)0x5f, (byte)0x75, (byte)0x63, (byte)0x1b, (byte)0x23, (byte)0x3d, (byte)0x68, (byte)0x2a, (byte)0x65, (byte)0xe8, (byte)0x91,
            (byte)0xf6, (byte)0xff, (byte)0x13, (byte)0x58, (byte)0xf1, (byte)0x47, (byte)0x0a, (byte)0x7f, (byte)0xc5, (byte)0xa7, (byte)0xe7, (byte)0x61, (byte)0x5a, (byte)0x06, (byte)0x46, (byte)0x44,
            (byte)0x42, (byte)0x04, (byte)0xa0, (byte)0xdb, (byte)0x39, (byte)0x86, (byte)0x54, (byte)0xaa, (byte)0x8c, (byte)0x34, (byte)0x21, (byte)0x8b, (byte)0xf8, (byte)0x0c, (byte)0x74, (byte)0x67
        },
        new byte[]
            {
                (byte)0x68, (byte)0x8d, (byte)0xca, (byte)0x4d, (byte)0x73, (byte)0x4b, (byte)0x4e, (byte)0x2a, (byte)0xd4, (byte)0x52, (byte)0x26, (byte)0xb3, (byte)0x54, (byte)0x1e, (byte)0x19, (byte)0x1f,
                (byte)0x22, (byte)0x03, (byte)0x46, (byte)0x3d, (byte)0x2d, (byte)0x4a, (byte)0x53, (byte)0x83, (byte)0x13, (byte)0x8a, (byte)0xb7, (byte)0xd5, (byte)0x25, (byte)0x79, (byte)0xf5, (byte)0xbd,
                (byte)0x58, (byte)0x2f, (byte)0x0d, (byte)0x02, (byte)0xed, (byte)0x51, (byte)0x9e, (byte)0x11, (byte)0xf2, (byte)0x3e, (byte)0x55, (byte)0x5e, (byte)0xd1, (byte)0x16, (byte)0x3c, (byte)0x66,
                (byte)0x70, (byte)0x5d, (byte)0xf3, (byte)0x45, (byte)0x40, (byte)0xcc, (byte)0xe8, (byte)0x94, (byte)0x56, (byte)0x08, (byte)0xce, (byte)0x1a, (byte)0x3a, (byte)0xd2, (byte)0xe1, (byte)0xdf,
                (byte)0xb5, (byte)0x38, (byte)0x6e, (byte)0x0e, (byte)0xe5, (byte)0xf4, (byte)0xf9, (byte)0x86, (byte)0xe9, (byte)0x4f, (byte)0xd6, (byte)0x85, (byte)0x23, (byte)0xcf, (byte)0x32, (byte)0x99,
                (byte)0x31, (byte)0x14, (byte)0xae, (byte)0xee, (byte)0xc8, (byte)0x48, (byte)0xd3, (byte)0x30, (byte)0xa1, (byte)0x92, (byte)0x41, (byte)0xb1, (byte)0x18, (byte)0xc4, (byte)0x2c, (byte)0x71,
                (byte)0x72, (byte)0x44, (byte)0x15, (byte)0xfd, (byte)0x37, (byte)0xbe, (byte)0x5f, (byte)0xaa, (byte)0x9b, (byte)0x88, (byte)0xd8, (byte)0xab, (byte)0x89, (byte)0x9c, (byte)0xfa, (byte)0x60,
                (byte)0xea, (byte)0xbc, (byte)0x62, (byte)0x0c, (byte)0x24, (byte)0xa6, (byte)0xa8, (byte)0xec, (byte)0x67, (byte)0x20, (byte)0xdb, (byte)0x7c, (byte)0x28, (byte)0xdd, (byte)0xac, (byte)0x5b,
                (byte)0x34, (byte)0x7e, (byte)0x10, (byte)0xf1, (byte)0x7b, (byte)0x8f, (byte)0x63, (byte)0xa0, (byte)0x05, (byte)0x9a, (byte)0x43, (byte)0x77, (byte)0x21, (byte)0xbf, (byte)0x27, (byte)0x09,
                (byte)0xc3, (byte)0x9f, (byte)0xb6, (byte)0xd7, (byte)0x29, (byte)0xc2, (byte)0xeb, (byte)0xc0, (byte)0xa4, (byte)0x8b, (byte)0x8c, (byte)0x1d, (byte)0xfb, (byte)0xff, (byte)0xc1, (byte)0xb2,
                (byte)0x97, (byte)0x2e, (byte)0xf8, (byte)0x65, (byte)0xf6, (byte)0x75, (byte)0x07, (byte)0x04, (byte)0x49, (byte)0x33, (byte)0xe4, (byte)0xd9, (byte)0xb9, (byte)0xd0, (byte)0x42, (byte)0xc7,
                (byte)0x6c, (byte)0x90, (byte)0x00, (byte)0x8e, (byte)0x6f, (byte)0x50, (byte)0x01, (byte)0xc5, (byte)0xda, (byte)0x47, (byte)0x3f, (byte)0xcd, (byte)0x69, (byte)0xa2, (byte)0xe2, (byte)0x7a,
                (byte)0xa7, (byte)0xc6, (byte)0x93, (byte)0x0f, (byte)0x0a, (byte)0x06, (byte)0xe6, (byte)0x2b, (byte)0x96, (byte)0xa3, (byte)0x1c, (byte)0xaf, (byte)0x6a, (byte)0x12, (byte)0x84, (byte)0x39,
                (byte)0xe7, (byte)0xb0, (byte)0x82, (byte)0xf7, (byte)0xfe, (byte)0x9d, (byte)0x87, (byte)0x5c, (byte)0x81, (byte)0x35, (byte)0xde, (byte)0xb4, (byte)0xa5, (byte)0xfc, (byte)0x80, (byte)0xef,
                (byte)0xcb, (byte)0xbb, (byte)0x6b, (byte)0x76, (byte)0xba, (byte)0x5a, (byte)0x7d, (byte)0x78, (byte)0x0b, (byte)0x95, (byte)0xe3, (byte)0xad, (byte)0x74, (byte)0x98, (byte)0x3b, (byte)0x36,
                (byte)0x64, (byte)0x6d, (byte)0xdc, (byte)0xf0, (byte)0x59, (byte)0xa9, (byte)0x4c, (byte)0x17, (byte)0x7f, (byte)0x91, (byte)0xb8, (byte)0xc9, (byte)0x57, (byte)0x1b, (byte)0xe0, (byte)0x61
            }
    };

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
