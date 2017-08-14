package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;


/*
* Reference implementation of DSTU7624 national Ukrainian standard of block encryption.
* Thanks to Roman Oliynikov' native C implementation:
* https://github.com/Roman-Oliynikov/Kalyna-reference
*
* DSTU7564 is very similar to AES but with some security improvements in key schedule algorithm
* and supports different block and key lengths (128/256/512 bits).
*/
public class DSTU7624Engine
    implements BlockCipher
{

    private static final int BITS_IN_WORD = 64;
    private static final int BITS_IN_BYTE = 8;
    private static final int BITS_IN_LONG = 64;

//    private static final int REDUCTION_POLYNOMIAL = 0x011d; /* x^8 + x^4 + x^3 + x^2 + 1 */

    private long[] internalState;
    private long[] workingKey;
    private long[][] roundKeys;

    /* Number of 64-bit words in block */
    private int wordsInBlock;

    /* Number of 64-bit words in key */
    private int wordsInKey;

    /* Number of encryption rounds depending on key length */
    private static final int ROUNDS_128 = 10;
    private static final int ROUNDS_256 = 14;
    private static final int ROUNDS_512 = 18;

    private int roundsAmount;

    private boolean forEncryption;

    private byte[] internalStateBytes;
    private byte[] tempInternalStateBytes;

    public DSTU7624Engine(int blockBitLength)
        throws IllegalArgumentException
    {
        /* DSTU7624 supports 128 | 256 | 512 key/block sizes */
        if (blockBitLength != 128 && blockBitLength != 256 && blockBitLength != 512)
        {
            throw new IllegalArgumentException("unsupported block length: only 128/256/512 are allowed");
        }

        wordsInBlock = blockBitLength / BITS_IN_WORD;
        internalState = new long[wordsInBlock];

        internalStateBytes = new byte[internalState.length * BITS_IN_LONG / BITS_IN_BYTE];
        tempInternalStateBytes = new byte[internalState.length * BITS_IN_LONG / BITS_IN_BYTE];
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof KeyParameter)
        {
            this.forEncryption = forEncryption;

            byte[] keyBytes = ((KeyParameter)params).getKey();
            int keyBitLength = keyBytes.length * BITS_IN_BYTE;
            int blockBitLength = wordsInBlock * BITS_IN_WORD;

            if (keyBitLength != 128 && keyBitLength != 256 && keyBitLength != 512)
            {
                throw new IllegalArgumentException("unsupported key length: only 128/256/512 are allowed");
            }

            /* Limitations on key lengths depending on block lengths. See table 6.1 in standard */
            if (blockBitLength == 128)
            {
                if (keyBitLength == 512)
                {
                    throw new IllegalArgumentException("Unsupported key length");
                }
            }

            if (blockBitLength == 256)
            {
                if (keyBitLength == 128)
                {
                    throw new IllegalArgumentException("Unsupported key length");
                }
            }

            if (blockBitLength == 512)
            {
                if (keyBitLength != 512)
                {
                    throw new IllegalArgumentException("Unsupported key length");
                }
            }

            switch (keyBitLength)
            {
            case 128:
                roundsAmount = ROUNDS_128;
                break;
            case 256:
                roundsAmount = ROUNDS_256;
                break;
            case 512:
                roundsAmount = ROUNDS_512;
                break;
            }

            wordsInKey = keyBitLength / BITS_IN_WORD;

            /* +1 round key as defined in standard */
            roundKeys = new long[roundsAmount + 1][];
            for (int roundKeyIndex = 0; roundKeyIndex < roundKeys.length; roundKeyIndex++)
            {
                roundKeys[roundKeyIndex] = new long[wordsInBlock];
            }

            workingKey = new long[wordsInKey];

            if (keyBytes.length != wordsInKey * BITS_IN_WORD / BITS_IN_BYTE)
            {
                throw new IllegalArgumentException("Invalid key parameter passed to DSTU7624Engine init");
            }

            /* Unpack encryption key bytes to words */
            Pack.littleEndianToLong(keyBytes, 0, workingKey);

            long[] tempKeys = new long[wordsInBlock];

            /* KSA in DSTU7624 is strengthened to mitigate known weaknesses in AES KSA (eprint.iacr.org/2012/260.pdf) */
            workingKeyExpandKT(workingKey, tempKeys);
            workingKeyExpandEven(workingKey, tempKeys);
            workingKeyExpandOdd();
        }
        else
        {
            throw new IllegalArgumentException("Invalid parameter passed to DSTU7624Engine init");
        }
    }

    public String getAlgorithmName()
    {
        return "DSTU7624";
    }

    public int getBlockSize()
    {
        return wordsInBlock * BITS_IN_WORD / BITS_IN_BYTE;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (workingKey == null)
        {
            throw new IllegalStateException("DSTU7624 engine not initialised");
        }

        if (inOff + getBlockSize() > in.length)
        {
            throw new DataLengthException("Input buffer too short");
        }

        if (outOff + getBlockSize() > out.length)
        {
            throw new OutputLengthException("Output buffer too short");
        }


        if (forEncryption)
        {
            int round = 0;

            /* Unpack */
            Pack.littleEndianToLong(in, inOff, internalState);

            /* Encrypt */
            for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
            {
                internalState[wordIndex] += roundKeys[round][wordIndex];
            }

            for (round = 1; round < roundsAmount; round++)
            {
                SubBytes();
                ShiftRows();
                MixColumns(mdsMatrix); // equals to multiplication on matrix

                for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
                {
                    internalState[wordIndex] ^= roundKeys[round][wordIndex];
                }
            }

            SubBytes();
            ShiftRows();
            MixColumns(mdsMatrix); // equals to multiplication on matrix

            for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
            {
                internalState[wordIndex] += roundKeys[roundsAmount][wordIndex];
            }


            /* Pack */
            Pack.longToLittleEndian(internalState, out, outOff);

        }
        else
        {
            int round = roundsAmount;

            /* Unpack */
            Pack.littleEndianToLong(in, inOff, internalState);

            /* Decrypt */
            for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
            {
                internalState[wordIndex] -= roundKeys[round][wordIndex];
            }

            for (round = roundsAmount - 1; round > 0; round--)
            {
                MixColumns(mdsInvMatrix); // equals to multiplication on matrix
                InvShiftRows();
                InvSubBytes();

                for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
                {
                    internalState[wordIndex] ^= roundKeys[round][wordIndex];
                }
            }
            MixColumns(mdsInvMatrix); // equals to multiplication on matrix
            InvShiftRows();
            InvSubBytes();

            for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
            {
                internalState[wordIndex] -= roundKeys[0][wordIndex];
            }

            /* Pack */
            Pack.longToLittleEndian(internalState, out, outOff);

        }

        return getBlockSize();
    }

    public void reset()
    {
        Arrays.fill(internalState, 0);
        Arrays.fill(internalStateBytes, (byte)0x00);
        Arrays.fill(tempInternalStateBytes, (byte)0x00);
    }


    private void workingKeyExpandKT(long[] workingKey, long[] tempKeys)
    {
        long[] k0 = new long[wordsInBlock];
        long[] k1 = new long[wordsInBlock];

        internalState = new long[wordsInBlock];
        internalState[0] += wordsInBlock + wordsInKey + 1;

        if (wordsInBlock == wordsInKey)
        {
            System.arraycopy(workingKey, 0, k0, 0, k0.length);
            System.arraycopy(workingKey, 0, k1, 0, k1.length);
        }
        else
        {
            System.arraycopy(workingKey, 0, k0, 0, wordsInBlock);
            System.arraycopy(workingKey, wordsInBlock, k1, 0, wordsInBlock);
        }


        for (int wordIndex = 0; wordIndex < internalState.length; wordIndex++)
        {
            internalState[wordIndex] += k0[wordIndex];
        }

        SubBytes();
        ShiftRows();
        MixColumns(mdsMatrix); // equals to multiplication on matrix

        for (int wordIndex = 0; wordIndex < internalState.length; wordIndex++)
        {
            internalState[wordIndex] ^= k1[wordIndex];
        }

        SubBytes();
        ShiftRows();
        MixColumns(mdsMatrix); // equals to multiplication on matrix

        for (int wordIndex = 0; wordIndex < internalState.length; wordIndex++)
        {
            internalState[wordIndex] += k0[wordIndex];
        }

        SubBytes();
        ShiftRows();
        MixColumns(mdsMatrix); // equals to multiplication on matrix

        System.arraycopy(internalState, 0, tempKeys, 0, wordsInBlock);
    }

    private void workingKeyExpandEven(long[] workingKey, long[] tempKey)
    {
        long[] initialData = new long[wordsInKey];
        long[] tempRoundKey = new long[wordsInBlock];
        long[] tmv = new long[wordsInBlock];

        int round = 0;

        System.arraycopy(workingKey, 0, initialData, 0, wordsInKey);

        for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
        {
            tmv[wordIndex] = 0x0001000100010001L;
        }

        while (true)
        {
            System.arraycopy(tempKey, 0, internalState, 0, wordsInBlock);

            for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
            {
                internalState[wordIndex] += tmv[wordIndex];
            }

            System.arraycopy(internalState, 0, tempRoundKey, 0, wordsInBlock);
            System.arraycopy(initialData, 0, internalState, 0, wordsInBlock);

            for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
            {
                internalState[wordIndex] += tempRoundKey[wordIndex];
            }

            SubBytes();
            ShiftRows();
            MixColumns(mdsMatrix); // equals to multiplication on matrix

            for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
            {
                internalState[wordIndex] ^= tempRoundKey[wordIndex];
            }

            SubBytes();
            ShiftRows();
            MixColumns(mdsMatrix); // equals to multiplication on matrix

            for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
            {
                internalState[wordIndex] += tempRoundKey[wordIndex];
            }

            System.arraycopy(internalState, 0, roundKeys[round], 0, wordsInBlock);

            if (roundsAmount == round)
            {
                break;
            }
            if (wordsInBlock != wordsInKey)
            {
                round += 2;
                ShiftLeft(tmv);
                System.arraycopy(tempKey, 0, internalState, 0, wordsInBlock);

                for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
                {
                    internalState[wordIndex] += tmv[wordIndex];
                }

                System.arraycopy(internalState, 0, tempRoundKey, 0, wordsInBlock);
                System.arraycopy(initialData, wordsInBlock, internalState, 0, wordsInBlock);

                for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
                {
                    internalState[wordIndex] += tempRoundKey[wordIndex];
                }

                SubBytes();
                ShiftRows();
                MixColumns(mdsMatrix); // equals to multiplication on matrix

                for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
                {
                    internalState[wordIndex] ^= tempRoundKey[wordIndex];
                }

                SubBytes();
                ShiftRows();
                MixColumns(mdsMatrix); // equals to multiplication on matrix

                for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
                {
                    internalState[wordIndex] += tempRoundKey[wordIndex];
                }

                System.arraycopy(internalState, 0, roundKeys[round], 0, wordsInBlock);

                if (roundsAmount == round)
                {
                    break;
                }
            }

            round += 2;
            ShiftLeft(tmv);

            long temp = initialData[0];
            System.arraycopy(initialData, 1, initialData, 0, initialData.length - 1);
            initialData[initialData.length - 1] = temp;

        }
    }

    private void workingKeyExpandOdd()
    {
        for (int roundIndex = 1; roundIndex < roundsAmount; roundIndex += 2)
        {
            System.arraycopy(roundKeys[roundIndex - 1], 0, roundKeys[roundIndex], 0, wordsInBlock);
            RotateLeft(roundKeys[roundIndex]);
        }
    }


    private void SubBytes()
    {
        for (int i = 0; i < wordsInBlock; i++)
        {
            internalState[i] = sboxesForEncryption[0][(int)(internalState[i] & 0x00000000000000FFL)] & 0x00000000000000FFL |
                (long)sboxesForEncryption[1][(int)((internalState[i] & 0x000000000000FF00L) >>> 8)] << 8 & 0x000000000000FF00L |
                (long)sboxesForEncryption[2][(int)((internalState[i] & 0x0000000000FF0000L) >>> 16)] << 16 & 0x0000000000FF0000L |
                (long)sboxesForEncryption[3][(int)((internalState[i] & 0x00000000FF000000L) >>> 24)] << 24 & 0x00000000FF000000L |
                (long)sboxesForEncryption[0][(int)((internalState[i] & 0x000000FF00000000L) >>> 32)] << 32 & 0x000000FF00000000L |
                (long)sboxesForEncryption[1][(int)((internalState[i] & 0x0000FF0000000000L) >>> 40)] << 40 & 0x0000FF0000000000L |
                (long)sboxesForEncryption[2][(int)((internalState[i] & 0x00FF000000000000L) >>> 48)] << 48 & 0x00FF000000000000L |
                (long)sboxesForEncryption[3][(int)((internalState[i] & 0xFF00000000000000L) >>> 56)] << 56 & 0xFF00000000000000L;
        }
    }

    private void InvSubBytes()
    {
        for (int i = 0; i < wordsInBlock; i++)
        {
            internalState[i] = sboxesForDecryption[0][(int)(internalState[i] & 0x00000000000000FFL)] & 0x00000000000000FFL |
                (long)sboxesForDecryption[1][(int)((internalState[i] & 0x000000000000FF00L) >>> 8)] << 8 & 0x000000000000FF00L |
                (long)sboxesForDecryption[2][(int)((internalState[i] & 0x0000000000FF0000L) >>> 16)] << 16 & 0x0000000000FF0000L |
                (long)sboxesForDecryption[3][(int)((internalState[i] & 0x00000000FF000000L) >>> 24)] << 24 & 0x00000000FF000000L |
                (long)sboxesForDecryption[0][(int)((internalState[i] & 0x000000FF00000000L) >>> 32)] << 32 & 0x000000FF00000000L |
                (long)sboxesForDecryption[1][(int)((internalState[i] & 0x0000FF0000000000L) >>> 40)] << 40 & 0x0000FF0000000000L |
                (long)sboxesForDecryption[2][(int)((internalState[i] & 0x00FF000000000000L) >>> 48)] << 48 & 0x00FF000000000000L |
                (long)sboxesForDecryption[3][(int)((internalState[i] & 0xFF00000000000000L) >>> 56)] << 56 & 0xFF00000000000000L;
        }
    }

    private void ShiftRows()
    {
        int row, col;
        int shift = -1;

        Pack.longToLittleEndian(internalState, internalStateBytes, 0);

        for (row = 0; row < BITS_IN_LONG / BITS_IN_BYTE; row++)
        {
            if (row % (BITS_IN_LONG / BITS_IN_BYTE / wordsInBlock) == 0)
            {
                shift += 1;
            }
            for (col = 0; col < wordsInBlock; col++)
            {
                tempInternalStateBytes[row + ((col + shift) % wordsInBlock) * BITS_IN_LONG / BITS_IN_BYTE] = internalStateBytes[row + col * BITS_IN_LONG / BITS_IN_BYTE];
            }
        }

        Pack.littleEndianToLong(tempInternalStateBytes, 0, internalState);
    }

    private void InvShiftRows()
    {
        int row, col;
        int shift = -1;

        Pack.longToLittleEndian(internalState, internalStateBytes, 0);

        for (row = 0; row < BITS_IN_LONG / BITS_IN_BYTE; row++)
        {
            if (row % (BITS_IN_LONG / BITS_IN_BYTE / wordsInBlock) == 0)
            {
                shift += 1;
            }
            for (col = 0; col < wordsInBlock; col++)
            {
                tempInternalStateBytes[row + col * BITS_IN_LONG / BITS_IN_BYTE] = internalStateBytes[row + ((col + shift) % wordsInBlock) * BITS_IN_LONG / BITS_IN_BYTE];
            }
        }

        Pack.littleEndianToLong(tempInternalStateBytes, 0, internalState);
    }

    private void MixColumns(byte[][] matrix)
    {
        int col, row, b;
        byte product;
        long result;

        Pack.longToLittleEndian(internalState, internalStateBytes, 0);

        long shift;
        for (col = 0; col < wordsInBlock; ++col)
        {
            result = 0;
            shift = 0xFF00000000000000L;

            for (row = BITS_IN_LONG / BITS_IN_BYTE - 1; row >= 0; --row)
            {
                product = 0;
                for (b = BITS_IN_LONG / BITS_IN_BYTE - 1; b >= 0; --b)
                {
                    product ^= MultiplyGF(internalStateBytes[b + col * BITS_IN_LONG / BITS_IN_BYTE], matrix[row][b]);
                }

                result |= ((long)product << (row * BITS_IN_LONG / BITS_IN_BYTE) & shift);
                shift >>>= 8;

            }

            internalState[col] = result;
        }
    }

    private byte MultiplyGF(byte x, byte y)
    {
        int u = x & 0xFF, v = y & 0xFF;
        int r = u & -(v & 1);

        for (int i = 1; i < BITS_IN_BYTE; i++)
        {
            u <<= 1;
            v >>>= 1;
            r ^= u & -(v & 1);
        }

        int hi = r & 0xFF00;
        r ^= hi ^ (hi >>> 4) ^ (hi >>> 5) ^ (hi >>> 6) ^ (hi >>> 8);
        hi = r & 0x0F00;
        r ^= hi ^ (hi >>> 4) ^ (hi >>> 5) ^ (hi >>> 6) ^ (hi >>> 8);

        return (byte)r;
    }

    private void ShiftLeft(long[] value)
    {
        for (int i = 0; i < value.length; i++)
        {
            value[i] <<= 1;
        }
        //reversing state
        for (int i = 0; i < value.length / 2; i++)
        {
            long temp = value[i];
            value[i] = value[value.length - i - 1];
            value[value.length - i - 1] = temp;
        }
    }

    private void RotateLeft(long[] value)
    {
        int rotateBytesLength = 2 * value.length + 3;
        int bytesLength = value.length * (BITS_IN_WORD / BITS_IN_BYTE);

        byte[] bytes = new byte[value.length * BITS_IN_LONG / BITS_IN_BYTE];
        Pack.longToLittleEndian(value, bytes, 0);

        byte[] buffer = new byte[rotateBytesLength];
        System.arraycopy(bytes, 0, buffer, 0, rotateBytesLength);
        System.arraycopy(bytes, rotateBytesLength, bytes, 0, bytesLength - rotateBytesLength);
        System.arraycopy(buffer, 0, bytes, bytesLength - rotateBytesLength, rotateBytesLength);

        Pack.littleEndianToLong(bytes, 0, value);
    }


    //region MATRICES AND S-BOXES
    private byte[][] mdsMatrix =
        {
            new byte[]{(byte)0x01, (byte)0x01, (byte)0x05, (byte)0x01, (byte)0x08, (byte)0x06, (byte)0x07, (byte)0x04},
            new byte[]{(byte)0x04, (byte)0x01, (byte)0x01, (byte)0x05, (byte)0x01, (byte)0x08, (byte)0x06, (byte)0x07},
            new byte[]{(byte)0x07, (byte)0x04, (byte)0x01, (byte)0x01, (byte)0x05, (byte)0x01, (byte)0x08, (byte)0x06},
            new byte[]{(byte)0x06, (byte)0x07, (byte)0x04, (byte)0x01, (byte)0x01, (byte)0x05, (byte)0x01, (byte)0x08},
            new byte[]{(byte)0x08, (byte)0x06, (byte)0x07, (byte)0x04, (byte)0x01, (byte)0x01, (byte)0x05, (byte)0x01},
            new byte[]{(byte)0x01, (byte)0x08, (byte)0x06, (byte)0x07, (byte)0x04, (byte)0x01, (byte)0x01, (byte)0x05},
            new byte[]{(byte)0x05, (byte)0x01, (byte)0x08, (byte)0x06, (byte)0x07, (byte)0x04, (byte)0x01, (byte)0x01},
            new byte[]{(byte)0x01, (byte)0x05, (byte)0x01, (byte)0x08, (byte)0x06, (byte)0x07, (byte)0x04, (byte)0x01}
        };

    private byte[][] mdsInvMatrix =
        {
            new byte[]{(byte)0xAD, (byte)0x95, (byte)0x76, (byte)0xA8, (byte)0x2F, (byte)0x49, (byte)0xD7, (byte)0xCA},
            new byte[]{(byte)0xCA, (byte)0xAD, (byte)0x95, (byte)0x76, (byte)0xA8, (byte)0x2F, (byte)0x49, (byte)0xD7},
            new byte[]{(byte)0xD7, (byte)0xCA, (byte)0xAD, (byte)0x95, (byte)0x76, (byte)0xA8, (byte)0x2F, (byte)0x49},
            new byte[]{(byte)0x49, (byte)0xD7, (byte)0xCA, (byte)0xAD, (byte)0x95, (byte)0x76, (byte)0xA8, (byte)0x2F},
            new byte[]{(byte)0x2F, (byte)0x49, (byte)0xD7, (byte)0xCA, (byte)0xAD, (byte)0x95, (byte)0x76, (byte)0xA8},
            new byte[]{(byte)0xA8, (byte)0x2F, (byte)0x49, (byte)0xD7, (byte)0xCA, (byte)0xAD, (byte)0x95, (byte)0x76},
            new byte[]{(byte)0x76, (byte)0xA8, (byte)0x2F, (byte)0x49, (byte)0xD7, (byte)0xCA, (byte)0xAD, (byte)0x95},
            new byte[]{(byte)0x95, (byte)0x76, (byte)0xA8, (byte)0x2F, (byte)0x49, (byte)0xD7, (byte)0xCA, (byte)0xAD}
        };


    private byte[][] sboxesForEncryption =
        {
            new byte[]
                {
                    (byte)0xa8, (byte)0x43, (byte)0x5f, (byte)0x06, (byte)0x6b, (byte)0x75, (byte)0x6c, (byte)0x59,
                    (byte)0x71, (byte)0xdf, (byte)0x87, (byte)0x95, (byte)0x17, (byte)0xf0, (byte)0xd8, (byte)0x09,
                    (byte)0x6d, (byte)0xf3, (byte)0x1d, (byte)0xcb, (byte)0xc9, (byte)0x4d, (byte)0x2c, (byte)0xaf,
                    (byte)0x79, (byte)0xe0, (byte)0x97, (byte)0xfd, (byte)0x6f, (byte)0x4b, (byte)0x45, (byte)0x39,
                    (byte)0x3e, (byte)0xdd, (byte)0xa3, (byte)0x4f, (byte)0xb4, (byte)0xb6, (byte)0x9a, (byte)0x0e,
                    (byte)0x1f, (byte)0xbf, (byte)0x15, (byte)0xe1, (byte)0x49, (byte)0xd2, (byte)0x93, (byte)0xc6,
                    (byte)0x92, (byte)0x72, (byte)0x9e, (byte)0x61, (byte)0xd1, (byte)0x63, (byte)0xfa, (byte)0xee,
                    (byte)0xf4, (byte)0x19, (byte)0xd5, (byte)0xad, (byte)0x58, (byte)0xa4, (byte)0xbb, (byte)0xa1,
                    (byte)0xdc, (byte)0xf2, (byte)0x83, (byte)0x37, (byte)0x42, (byte)0xe4, (byte)0x7a, (byte)0x32,
                    (byte)0x9c, (byte)0xcc, (byte)0xab, (byte)0x4a, (byte)0x8f, (byte)0x6e, (byte)0x04, (byte)0x27,
                    (byte)0x2e, (byte)0xe7, (byte)0xe2, (byte)0x5a, (byte)0x96, (byte)0x16, (byte)0x23, (byte)0x2b,
                    (byte)0xc2, (byte)0x65, (byte)0x66, (byte)0x0f, (byte)0xbc, (byte)0xa9, (byte)0x47, (byte)0x41,
                    (byte)0x34, (byte)0x48, (byte)0xfc, (byte)0xb7, (byte)0x6a, (byte)0x88, (byte)0xa5, (byte)0x53,
                    (byte)0x86, (byte)0xf9, (byte)0x5b, (byte)0xdb, (byte)0x38, (byte)0x7b, (byte)0xc3, (byte)0x1e,
                    (byte)0x22, (byte)0x33, (byte)0x24, (byte)0x28, (byte)0x36, (byte)0xc7, (byte)0xb2, (byte)0x3b,
                    (byte)0x8e, (byte)0x77, (byte)0xba, (byte)0xf5, (byte)0x14, (byte)0x9f, (byte)0x08, (byte)0x55,
                    (byte)0x9b, (byte)0x4c, (byte)0xfe, (byte)0x60, (byte)0x5c, (byte)0xda, (byte)0x18, (byte)0x46,
                    (byte)0xcd, (byte)0x7d, (byte)0x21, (byte)0xb0, (byte)0x3f, (byte)0x1b, (byte)0x89, (byte)0xff,
                    (byte)0xeb, (byte)0x84, (byte)0x69, (byte)0x3a, (byte)0x9d, (byte)0xd7, (byte)0xd3, (byte)0x70,
                    (byte)0x67, (byte)0x40, (byte)0xb5, (byte)0xde, (byte)0x5d, (byte)0x30, (byte)0x91, (byte)0xb1,
                    (byte)0x78, (byte)0x11, (byte)0x01, (byte)0xe5, (byte)0x00, (byte)0x68, (byte)0x98, (byte)0xa0,
                    (byte)0xc5, (byte)0x02, (byte)0xa6, (byte)0x74, (byte)0x2d, (byte)0x0b, (byte)0xa2, (byte)0x76,
                    (byte)0xb3, (byte)0xbe, (byte)0xce, (byte)0xbd, (byte)0xae, (byte)0xe9, (byte)0x8a, (byte)0x31,
                    (byte)0x1c, (byte)0xec, (byte)0xf1, (byte)0x99, (byte)0x94, (byte)0xaa, (byte)0xf6, (byte)0x26,
                    (byte)0x2f, (byte)0xef, (byte)0xe8, (byte)0x8c, (byte)0x35, (byte)0x03, (byte)0xd4, (byte)0x7f,
                    (byte)0xfb, (byte)0x05, (byte)0xc1, (byte)0x5e, (byte)0x90, (byte)0x20, (byte)0x3d, (byte)0x82,
                    (byte)0xf7, (byte)0xea, (byte)0x0a, (byte)0x0d, (byte)0x7e, (byte)0xf8, (byte)0x50, (byte)0x1a,
                    (byte)0xc4, (byte)0x07, (byte)0x57, (byte)0xb8, (byte)0x3c, (byte)0x62, (byte)0xe3, (byte)0xc8,
                    (byte)0xac, (byte)0x52, (byte)0x64, (byte)0x10, (byte)0xd0, (byte)0xd9, (byte)0x13, (byte)0x0c,
                    (byte)0x12, (byte)0x29, (byte)0x51, (byte)0xb9, (byte)0xcf, (byte)0xd6, (byte)0x73, (byte)0x8d,
                    (byte)0x81, (byte)0x54, (byte)0xc0, (byte)0xed, (byte)0x4e, (byte)0x44, (byte)0xa7, (byte)0x2a,
                    (byte)0x85, (byte)0x25, (byte)0xe6, (byte)0xca, (byte)0x7c, (byte)0x8b, (byte)0x56, (byte)0x80
                },

            new byte[]
                {
                    (byte)0xce, (byte)0xbb, (byte)0xeb, (byte)0x92, (byte)0xea, (byte)0xcb, (byte)0x13, (byte)0xc1,
                    (byte)0xe9, (byte)0x3a, (byte)0xd6, (byte)0xb2, (byte)0xd2, (byte)0x90, (byte)0x17, (byte)0xf8,
                    (byte)0x42, (byte)0x15, (byte)0x56, (byte)0xb4, (byte)0x65, (byte)0x1c, (byte)0x88, (byte)0x43,
                    (byte)0xc5, (byte)0x5c, (byte)0x36, (byte)0xba, (byte)0xf5, (byte)0x57, (byte)0x67, (byte)0x8d,
                    (byte)0x31, (byte)0xf6, (byte)0x64, (byte)0x58, (byte)0x9e, (byte)0xf4, (byte)0x22, (byte)0xaa,
                    (byte)0x75, (byte)0x0f, (byte)0x02, (byte)0xb1, (byte)0xdf, (byte)0x6d, (byte)0x73, (byte)0x4d,
                    (byte)0x7c, (byte)0x26, (byte)0x2e, (byte)0xf7, (byte)0x08, (byte)0x5d, (byte)0x44, (byte)0x3e,
                    (byte)0x9f, (byte)0x14, (byte)0xc8, (byte)0xae, (byte)0x54, (byte)0x10, (byte)0xd8, (byte)0xbc,
                    (byte)0x1a, (byte)0x6b, (byte)0x69, (byte)0xf3, (byte)0xbd, (byte)0x33, (byte)0xab, (byte)0xfa,
                    (byte)0xd1, (byte)0x9b, (byte)0x68, (byte)0x4e, (byte)0x16, (byte)0x95, (byte)0x91, (byte)0xee,
                    (byte)0x4c, (byte)0x63, (byte)0x8e, (byte)0x5b, (byte)0xcc, (byte)0x3c, (byte)0x19, (byte)0xa1,
                    (byte)0x81, (byte)0x49, (byte)0x7b, (byte)0xd9, (byte)0x6f, (byte)0x37, (byte)0x60, (byte)0xca,
                    (byte)0xe7, (byte)0x2b, (byte)0x48, (byte)0xfd, (byte)0x96, (byte)0x45, (byte)0xfc, (byte)0x41,
                    (byte)0x12, (byte)0x0d, (byte)0x79, (byte)0xe5, (byte)0x89, (byte)0x8c, (byte)0xe3, (byte)0x20,
                    (byte)0x30, (byte)0xdc, (byte)0xb7, (byte)0x6c, (byte)0x4a, (byte)0xb5, (byte)0x3f, (byte)0x97,
                    (byte)0xd4, (byte)0x62, (byte)0x2d, (byte)0x06, (byte)0xa4, (byte)0xa5, (byte)0x83, (byte)0x5f,
                    (byte)0x2a, (byte)0xda, (byte)0xc9, (byte)0x00, (byte)0x7e, (byte)0xa2, (byte)0x55, (byte)0xbf,
                    (byte)0x11, (byte)0xd5, (byte)0x9c, (byte)0xcf, (byte)0x0e, (byte)0x0a, (byte)0x3d, (byte)0x51,
                    (byte)0x7d, (byte)0x93, (byte)0x1b, (byte)0xfe, (byte)0xc4, (byte)0x47, (byte)0x09, (byte)0x86,
                    (byte)0x0b, (byte)0x8f, (byte)0x9d, (byte)0x6a, (byte)0x07, (byte)0xb9, (byte)0xb0, (byte)0x98,
                    (byte)0x18, (byte)0x32, (byte)0x71, (byte)0x4b, (byte)0xef, (byte)0x3b, (byte)0x70, (byte)0xa0,
                    (byte)0xe4, (byte)0x40, (byte)0xff, (byte)0xc3, (byte)0xa9, (byte)0xe6, (byte)0x78, (byte)0xf9,
                    (byte)0x8b, (byte)0x46, (byte)0x80, (byte)0x1e, (byte)0x38, (byte)0xe1, (byte)0xb8, (byte)0xa8,
                    (byte)0xe0, (byte)0x0c, (byte)0x23, (byte)0x76, (byte)0x1d, (byte)0x25, (byte)0x24, (byte)0x05,
                    (byte)0xf1, (byte)0x6e, (byte)0x94, (byte)0x28, (byte)0x9a, (byte)0x84, (byte)0xe8, (byte)0xa3,
                    (byte)0x4f, (byte)0x77, (byte)0xd3, (byte)0x85, (byte)0xe2, (byte)0x52, (byte)0xf2, (byte)0x82,
                    (byte)0x50, (byte)0x7a, (byte)0x2f, (byte)0x74, (byte)0x53, (byte)0xb3, (byte)0x61, (byte)0xaf,
                    (byte)0x39, (byte)0x35, (byte)0xde, (byte)0xcd, (byte)0x1f, (byte)0x99, (byte)0xac, (byte)0xad,
                    (byte)0x72, (byte)0x2c, (byte)0xdd, (byte)0xd0, (byte)0x87, (byte)0xbe, (byte)0x5e, (byte)0xa6,
                    (byte)0xec, (byte)0x04, (byte)0xc6, (byte)0x03, (byte)0x34, (byte)0xfb, (byte)0xdb, (byte)0x59,
                    (byte)0xb6, (byte)0xc2, (byte)0x01, (byte)0xf0, (byte)0x5a, (byte)0xed, (byte)0xa7, (byte)0x66,
                    (byte)0x21, (byte)0x7f, (byte)0x8a, (byte)0x27, (byte)0xc7, (byte)0xc0, (byte)0x29, (byte)0xd7
                },

            new byte[]
                {
                    (byte)0x93, (byte)0xd9, (byte)0x9a, (byte)0xb5, (byte)0x98, (byte)0x22, (byte)0x45, (byte)0xfc,
                    (byte)0xba, (byte)0x6a, (byte)0xdf, (byte)0x02, (byte)0x9f, (byte)0xdc, (byte)0x51, (byte)0x59,
                    (byte)0x4a, (byte)0x17, (byte)0x2b, (byte)0xc2, (byte)0x94, (byte)0xf4, (byte)0xbb, (byte)0xa3,
                    (byte)0x62, (byte)0xe4, (byte)0x71, (byte)0xd4, (byte)0xcd, (byte)0x70, (byte)0x16, (byte)0xe1,
                    (byte)0x49, (byte)0x3c, (byte)0xc0, (byte)0xd8, (byte)0x5c, (byte)0x9b, (byte)0xad, (byte)0x85,
                    (byte)0x53, (byte)0xa1, (byte)0x7a, (byte)0xc8, (byte)0x2d, (byte)0xe0, (byte)0xd1, (byte)0x72,
                    (byte)0xa6, (byte)0x2c, (byte)0xc4, (byte)0xe3, (byte)0x76, (byte)0x78, (byte)0xb7, (byte)0xb4,
                    (byte)0x09, (byte)0x3b, (byte)0x0e, (byte)0x41, (byte)0x4c, (byte)0xde, (byte)0xb2, (byte)0x90,
                    (byte)0x25, (byte)0xa5, (byte)0xd7, (byte)0x03, (byte)0x11, (byte)0x00, (byte)0xc3, (byte)0x2e,
                    (byte)0x92, (byte)0xef, (byte)0x4e, (byte)0x12, (byte)0x9d, (byte)0x7d, (byte)0xcb, (byte)0x35,
                    (byte)0x10, (byte)0xd5, (byte)0x4f, (byte)0x9e, (byte)0x4d, (byte)0xa9, (byte)0x55, (byte)0xc6,
                    (byte)0xd0, (byte)0x7b, (byte)0x18, (byte)0x97, (byte)0xd3, (byte)0x36, (byte)0xe6, (byte)0x48,
                    (byte)0x56, (byte)0x81, (byte)0x8f, (byte)0x77, (byte)0xcc, (byte)0x9c, (byte)0xb9, (byte)0xe2,
                    (byte)0xac, (byte)0xb8, (byte)0x2f, (byte)0x15, (byte)0xa4, (byte)0x7c, (byte)0xda, (byte)0x38,
                    (byte)0x1e, (byte)0x0b, (byte)0x05, (byte)0xd6, (byte)0x14, (byte)0x6e, (byte)0x6c, (byte)0x7e,
                    (byte)0x66, (byte)0xfd, (byte)0xb1, (byte)0xe5, (byte)0x60, (byte)0xaf, (byte)0x5e, (byte)0x33,
                    (byte)0x87, (byte)0xc9, (byte)0xf0, (byte)0x5d, (byte)0x6d, (byte)0x3f, (byte)0x88, (byte)0x8d,
                    (byte)0xc7, (byte)0xf7, (byte)0x1d, (byte)0xe9, (byte)0xec, (byte)0xed, (byte)0x80, (byte)0x29,
                    (byte)0x27, (byte)0xcf, (byte)0x99, (byte)0xa8, (byte)0x50, (byte)0x0f, (byte)0x37, (byte)0x24,
                    (byte)0x28, (byte)0x30, (byte)0x95, (byte)0xd2, (byte)0x3e, (byte)0x5b, (byte)0x40, (byte)0x83,
                    (byte)0xb3, (byte)0x69, (byte)0x57, (byte)0x1f, (byte)0x07, (byte)0x1c, (byte)0x8a, (byte)0xbc,
                    (byte)0x20, (byte)0xeb, (byte)0xce, (byte)0x8e, (byte)0xab, (byte)0xee, (byte)0x31, (byte)0xa2,
                    (byte)0x73, (byte)0xf9, (byte)0xca, (byte)0x3a, (byte)0x1a, (byte)0xfb, (byte)0x0d, (byte)0xc1,
                    (byte)0xfe, (byte)0xfa, (byte)0xf2, (byte)0x6f, (byte)0xbd, (byte)0x96, (byte)0xdd, (byte)0x43,
                    (byte)0x52, (byte)0xb6, (byte)0x08, (byte)0xf3, (byte)0xae, (byte)0xbe, (byte)0x19, (byte)0x89,
                    (byte)0x32, (byte)0x26, (byte)0xb0, (byte)0xea, (byte)0x4b, (byte)0x64, (byte)0x84, (byte)0x82,
                    (byte)0x6b, (byte)0xf5, (byte)0x79, (byte)0xbf, (byte)0x01, (byte)0x5f, (byte)0x75, (byte)0x63,
                    (byte)0x1b, (byte)0x23, (byte)0x3d, (byte)0x68, (byte)0x2a, (byte)0x65, (byte)0xe8, (byte)0x91,
                    (byte)0xf6, (byte)0xff, (byte)0x13, (byte)0x58, (byte)0xf1, (byte)0x47, (byte)0x0a, (byte)0x7f,
                    (byte)0xc5, (byte)0xa7, (byte)0xe7, (byte)0x61, (byte)0x5a, (byte)0x06, (byte)0x46, (byte)0x44,
                    (byte)0x42, (byte)0x04, (byte)0xa0, (byte)0xdb, (byte)0x39, (byte)0x86, (byte)0x54, (byte)0xaa,
                    (byte)0x8c, (byte)0x34, (byte)0x21, (byte)0x8b, (byte)0xf8, (byte)0x0c, (byte)0x74, (byte)0x67
                },

            new byte[]
                {
                    (byte)0x68, (byte)0x8d, (byte)0xca, (byte)0x4d, (byte)0x73, (byte)0x4b, (byte)0x4e, (byte)0x2a,
                    (byte)0xd4, (byte)0x52, (byte)0x26, (byte)0xb3, (byte)0x54, (byte)0x1e, (byte)0x19, (byte)0x1f,
                    (byte)0x22, (byte)0x03, (byte)0x46, (byte)0x3d, (byte)0x2d, (byte)0x4a, (byte)0x53, (byte)0x83,
                    (byte)0x13, (byte)0x8a, (byte)0xb7, (byte)0xd5, (byte)0x25, (byte)0x79, (byte)0xf5, (byte)0xbd,
                    (byte)0x58, (byte)0x2f, (byte)0x0d, (byte)0x02, (byte)0xed, (byte)0x51, (byte)0x9e, (byte)0x11,
                    (byte)0xf2, (byte)0x3e, (byte)0x55, (byte)0x5e, (byte)0xd1, (byte)0x16, (byte)0x3c, (byte)0x66,
                    (byte)0x70, (byte)0x5d, (byte)0xf3, (byte)0x45, (byte)0x40, (byte)0xcc, (byte)0xe8, (byte)0x94,
                    (byte)0x56, (byte)0x08, (byte)0xce, (byte)0x1a, (byte)0x3a, (byte)0xd2, (byte)0xe1, (byte)0xdf,
                    (byte)0xb5, (byte)0x38, (byte)0x6e, (byte)0x0e, (byte)0xe5, (byte)0xf4, (byte)0xf9, (byte)0x86,
                    (byte)0xe9, (byte)0x4f, (byte)0xd6, (byte)0x85, (byte)0x23, (byte)0xcf, (byte)0x32, (byte)0x99,
                    (byte)0x31, (byte)0x14, (byte)0xae, (byte)0xee, (byte)0xc8, (byte)0x48, (byte)0xd3, (byte)0x30,
                    (byte)0xa1, (byte)0x92, (byte)0x41, (byte)0xb1, (byte)0x18, (byte)0xc4, (byte)0x2c, (byte)0x71,
                    (byte)0x72, (byte)0x44, (byte)0x15, (byte)0xfd, (byte)0x37, (byte)0xbe, (byte)0x5f, (byte)0xaa,
                    (byte)0x9b, (byte)0x88, (byte)0xd8, (byte)0xab, (byte)0x89, (byte)0x9c, (byte)0xfa, (byte)0x60,
                    (byte)0xea, (byte)0xbc, (byte)0x62, (byte)0x0c, (byte)0x24, (byte)0xa6, (byte)0xa8, (byte)0xec,
                    (byte)0x67, (byte)0x20, (byte)0xdb, (byte)0x7c, (byte)0x28, (byte)0xdd, (byte)0xac, (byte)0x5b,
                    (byte)0x34, (byte)0x7e, (byte)0x10, (byte)0xf1, (byte)0x7b, (byte)0x8f, (byte)0x63, (byte)0xa0,
                    (byte)0x05, (byte)0x9a, (byte)0x43, (byte)0x77, (byte)0x21, (byte)0xbf, (byte)0x27, (byte)0x09,
                    (byte)0xc3, (byte)0x9f, (byte)0xb6, (byte)0xd7, (byte)0x29, (byte)0xc2, (byte)0xeb, (byte)0xc0,
                    (byte)0xa4, (byte)0x8b, (byte)0x8c, (byte)0x1d, (byte)0xfb, (byte)0xff, (byte)0xc1, (byte)0xb2,
                    (byte)0x97, (byte)0x2e, (byte)0xf8, (byte)0x65, (byte)0xf6, (byte)0x75, (byte)0x07, (byte)0x04,
                    (byte)0x49, (byte)0x33, (byte)0xe4, (byte)0xd9, (byte)0xb9, (byte)0xd0, (byte)0x42, (byte)0xc7,
                    (byte)0x6c, (byte)0x90, (byte)0x00, (byte)0x8e, (byte)0x6f, (byte)0x50, (byte)0x01, (byte)0xc5,
                    (byte)0xda, (byte)0x47, (byte)0x3f, (byte)0xcd, (byte)0x69, (byte)0xa2, (byte)0xe2, (byte)0x7a,
                    (byte)0xa7, (byte)0xc6, (byte)0x93, (byte)0x0f, (byte)0x0a, (byte)0x06, (byte)0xe6, (byte)0x2b,
                    (byte)0x96, (byte)0xa3, (byte)0x1c, (byte)0xaf, (byte)0x6a, (byte)0x12, (byte)0x84, (byte)0x39,
                    (byte)0xe7, (byte)0xb0, (byte)0x82, (byte)0xf7, (byte)0xfe, (byte)0x9d, (byte)0x87, (byte)0x5c,
                    (byte)0x81, (byte)0x35, (byte)0xde, (byte)0xb4, (byte)0xa5, (byte)0xfc, (byte)0x80, (byte)0xef,
                    (byte)0xcb, (byte)0xbb, (byte)0x6b, (byte)0x76, (byte)0xba, (byte)0x5a, (byte)0x7d, (byte)0x78,
                    (byte)0x0b, (byte)0x95, (byte)0xe3, (byte)0xad, (byte)0x74, (byte)0x98, (byte)0x3b, (byte)0x36,
                    (byte)0x64, (byte)0x6d, (byte)0xdc, (byte)0xf0, (byte)0x59, (byte)0xa9, (byte)0x4c, (byte)0x17,
                    (byte)0x7f, (byte)0x91, (byte)0xb8, (byte)0xc9, (byte)0x57, (byte)0x1b, (byte)0xe0, (byte)0x61
                }

        };


    private byte[][] sboxesForDecryption =
        {
            new byte[]
                {
                    (byte)0xa4, (byte)0xa2, (byte)0xa9, (byte)0xc5, (byte)0x4e, (byte)0xc9, (byte)0x03, (byte)0xd9,
                    (byte)0x7e, (byte)0x0f, (byte)0xd2, (byte)0xad, (byte)0xe7, (byte)0xd3, (byte)0x27, (byte)0x5b,
                    (byte)0xe3, (byte)0xa1, (byte)0xe8, (byte)0xe6, (byte)0x7c, (byte)0x2a, (byte)0x55, (byte)0x0c,
                    (byte)0x86, (byte)0x39, (byte)0xd7, (byte)0x8d, (byte)0xb8, (byte)0x12, (byte)0x6f, (byte)0x28,
                    (byte)0xcd, (byte)0x8a, (byte)0x70, (byte)0x56, (byte)0x72, (byte)0xf9, (byte)0xbf, (byte)0x4f,
                    (byte)0x73, (byte)0xe9, (byte)0xf7, (byte)0x57, (byte)0x16, (byte)0xac, (byte)0x50, (byte)0xc0,
                    (byte)0x9d, (byte)0xb7, (byte)0x47, (byte)0x71, (byte)0x60, (byte)0xc4, (byte)0x74, (byte)0x43,
                    (byte)0x6c, (byte)0x1f, (byte)0x93, (byte)0x77, (byte)0xdc, (byte)0xce, (byte)0x20, (byte)0x8c,
                    (byte)0x99, (byte)0x5f, (byte)0x44, (byte)0x01, (byte)0xf5, (byte)0x1e, (byte)0x87, (byte)0x5e,
                    (byte)0x61, (byte)0x2c, (byte)0x4b, (byte)0x1d, (byte)0x81, (byte)0x15, (byte)0xf4, (byte)0x23,
                    (byte)0xd6, (byte)0xea, (byte)0xe1, (byte)0x67, (byte)0xf1, (byte)0x7f, (byte)0xfe, (byte)0xda,
                    (byte)0x3c, (byte)0x07, (byte)0x53, (byte)0x6a, (byte)0x84, (byte)0x9c, (byte)0xcb, (byte)0x02,
                    (byte)0x83, (byte)0x33, (byte)0xdd, (byte)0x35, (byte)0xe2, (byte)0x59, (byte)0x5a, (byte)0x98,
                    (byte)0xa5, (byte)0x92, (byte)0x64, (byte)0x04, (byte)0x06, (byte)0x10, (byte)0x4d, (byte)0x1c,
                    (byte)0x97, (byte)0x08, (byte)0x31, (byte)0xee, (byte)0xab, (byte)0x05, (byte)0xaf, (byte)0x79,
                    (byte)0xa0, (byte)0x18, (byte)0x46, (byte)0x6d, (byte)0xfc, (byte)0x89, (byte)0xd4, (byte)0xc7,
                    (byte)0xff, (byte)0xf0, (byte)0xcf, (byte)0x42, (byte)0x91, (byte)0xf8, (byte)0x68, (byte)0x0a,
                    (byte)0x65, (byte)0x8e, (byte)0xb6, (byte)0xfd, (byte)0xc3, (byte)0xef, (byte)0x78, (byte)0x4c,
                    (byte)0xcc, (byte)0x9e, (byte)0x30, (byte)0x2e, (byte)0xbc, (byte)0x0b, (byte)0x54, (byte)0x1a,
                    (byte)0xa6, (byte)0xbb, (byte)0x26, (byte)0x80, (byte)0x48, (byte)0x94, (byte)0x32, (byte)0x7d,
                    (byte)0xa7, (byte)0x3f, (byte)0xae, (byte)0x22, (byte)0x3d, (byte)0x66, (byte)0xaa, (byte)0xf6,
                    (byte)0x00, (byte)0x5d, (byte)0xbd, (byte)0x4a, (byte)0xe0, (byte)0x3b, (byte)0xb4, (byte)0x17,
                    (byte)0x8b, (byte)0x9f, (byte)0x76, (byte)0xb0, (byte)0x24, (byte)0x9a, (byte)0x25, (byte)0x63,
                    (byte)0xdb, (byte)0xeb, (byte)0x7a, (byte)0x3e, (byte)0x5c, (byte)0xb3, (byte)0xb1, (byte)0x29,
                    (byte)0xf2, (byte)0xca, (byte)0x58, (byte)0x6e, (byte)0xd8, (byte)0xa8, (byte)0x2f, (byte)0x75,
                    (byte)0xdf, (byte)0x14, (byte)0xfb, (byte)0x13, (byte)0x49, (byte)0x88, (byte)0xb2, (byte)0xec,
                    (byte)0xe4, (byte)0x34, (byte)0x2d, (byte)0x96, (byte)0xc6, (byte)0x3a, (byte)0xed, (byte)0x95,
                    (byte)0x0e, (byte)0xe5, (byte)0x85, (byte)0x6b, (byte)0x40, (byte)0x21, (byte)0x9b, (byte)0x09,
                    (byte)0x19, (byte)0x2b, (byte)0x52, (byte)0xde, (byte)0x45, (byte)0xa3, (byte)0xfa, (byte)0x51,
                    (byte)0xc2, (byte)0xb5, (byte)0xd1, (byte)0x90, (byte)0xb9, (byte)0xf3, (byte)0x37, (byte)0xc1,
                    (byte)0x0d, (byte)0xba, (byte)0x41, (byte)0x11, (byte)0x38, (byte)0x7b, (byte)0xbe, (byte)0xd0,
                    (byte)0xd5, (byte)0x69, (byte)0x36, (byte)0xc8, (byte)0x62, (byte)0x1b, (byte)0x82, (byte)0x8f
                },

            new byte[]
                {
                    (byte)0x83, (byte)0xf2, (byte)0x2a, (byte)0xeb, (byte)0xe9, (byte)0xbf, (byte)0x7b, (byte)0x9c,
                    (byte)0x34, (byte)0x96, (byte)0x8d, (byte)0x98, (byte)0xb9, (byte)0x69, (byte)0x8c, (byte)0x29,
                    (byte)0x3d, (byte)0x88, (byte)0x68, (byte)0x06, (byte)0x39, (byte)0x11, (byte)0x4c, (byte)0x0e,
                    (byte)0xa0, (byte)0x56, (byte)0x40, (byte)0x92, (byte)0x15, (byte)0xbc, (byte)0xb3, (byte)0xdc,
                    (byte)0x6f, (byte)0xf8, (byte)0x26, (byte)0xba, (byte)0xbe, (byte)0xbd, (byte)0x31, (byte)0xfb,
                    (byte)0xc3, (byte)0xfe, (byte)0x80, (byte)0x61, (byte)0xe1, (byte)0x7a, (byte)0x32, (byte)0xd2,
                    (byte)0x70, (byte)0x20, (byte)0xa1, (byte)0x45, (byte)0xec, (byte)0xd9, (byte)0x1a, (byte)0x5d,
                    (byte)0xb4, (byte)0xd8, (byte)0x09, (byte)0xa5, (byte)0x55, (byte)0x8e, (byte)0x37, (byte)0x76,
                    (byte)0xa9, (byte)0x67, (byte)0x10, (byte)0x17, (byte)0x36, (byte)0x65, (byte)0xb1, (byte)0x95,
                    (byte)0x62, (byte)0x59, (byte)0x74, (byte)0xa3, (byte)0x50, (byte)0x2f, (byte)0x4b, (byte)0xc8,
                    (byte)0xd0, (byte)0x8f, (byte)0xcd, (byte)0xd4, (byte)0x3c, (byte)0x86, (byte)0x12, (byte)0x1d,
                    (byte)0x23, (byte)0xef, (byte)0xf4, (byte)0x53, (byte)0x19, (byte)0x35, (byte)0xe6, (byte)0x7f,
                    (byte)0x5e, (byte)0xd6, (byte)0x79, (byte)0x51, (byte)0x22, (byte)0x14, (byte)0xf7, (byte)0x1e,
                    (byte)0x4a, (byte)0x42, (byte)0x9b, (byte)0x41, (byte)0x73, (byte)0x2d, (byte)0xc1, (byte)0x5c,
                    (byte)0xa6, (byte)0xa2, (byte)0xe0, (byte)0x2e, (byte)0xd3, (byte)0x28, (byte)0xbb, (byte)0xc9,
                    (byte)0xae, (byte)0x6a, (byte)0xd1, (byte)0x5a, (byte)0x30, (byte)0x90, (byte)0x84, (byte)0xf9,
                    (byte)0xb2, (byte)0x58, (byte)0xcf, (byte)0x7e, (byte)0xc5, (byte)0xcb, (byte)0x97, (byte)0xe4,
                    (byte)0x16, (byte)0x6c, (byte)0xfa, (byte)0xb0, (byte)0x6d, (byte)0x1f, (byte)0x52, (byte)0x99,
                    (byte)0x0d, (byte)0x4e, (byte)0x03, (byte)0x91, (byte)0xc2, (byte)0x4d, (byte)0x64, (byte)0x77,
                    (byte)0x9f, (byte)0xdd, (byte)0xc4, (byte)0x49, (byte)0x8a, (byte)0x9a, (byte)0x24, (byte)0x38,
                    (byte)0xa7, (byte)0x57, (byte)0x85, (byte)0xc7, (byte)0x7c, (byte)0x7d, (byte)0xe7, (byte)0xf6,
                    (byte)0xb7, (byte)0xac, (byte)0x27, (byte)0x46, (byte)0xde, (byte)0xdf, (byte)0x3b, (byte)0xd7,
                    (byte)0x9e, (byte)0x2b, (byte)0x0b, (byte)0xd5, (byte)0x13, (byte)0x75, (byte)0xf0, (byte)0x72,
                    (byte)0xb6, (byte)0x9d, (byte)0x1b, (byte)0x01, (byte)0x3f, (byte)0x44, (byte)0xe5, (byte)0x87,
                    (byte)0xfd, (byte)0x07, (byte)0xf1, (byte)0xab, (byte)0x94, (byte)0x18, (byte)0xea, (byte)0xfc,
                    (byte)0x3a, (byte)0x82, (byte)0x5f, (byte)0x05, (byte)0x54, (byte)0xdb, (byte)0x00, (byte)0x8b,
                    (byte)0xe3, (byte)0x48, (byte)0x0c, (byte)0xca, (byte)0x78, (byte)0x89, (byte)0x0a, (byte)0xff,
                    (byte)0x3e, (byte)0x5b, (byte)0x81, (byte)0xee, (byte)0x71, (byte)0xe2, (byte)0xda, (byte)0x2c,
                    (byte)0xb8, (byte)0xb5, (byte)0xcc, (byte)0x6e, (byte)0xa8, (byte)0x6b, (byte)0xad, (byte)0x60,
                    (byte)0xc6, (byte)0x08, (byte)0x04, (byte)0x02, (byte)0xe8, (byte)0xf5, (byte)0x4f, (byte)0xa4,
                    (byte)0xf3, (byte)0xc0, (byte)0xce, (byte)0x43, (byte)0x25, (byte)0x1c, (byte)0x21, (byte)0x33,
                    (byte)0x0f, (byte)0xaf, (byte)0x47, (byte)0xed, (byte)0x66, (byte)0x63, (byte)0x93, (byte)0xaa
                },

            new byte[]
                {
                    (byte)0x45, (byte)0xd4, (byte)0x0b, (byte)0x43, (byte)0xf1, (byte)0x72, (byte)0xed, (byte)0xa4,
                    (byte)0xc2, (byte)0x38, (byte)0xe6, (byte)0x71, (byte)0xfd, (byte)0xb6, (byte)0x3a, (byte)0x95,
                    (byte)0x50, (byte)0x44, (byte)0x4b, (byte)0xe2, (byte)0x74, (byte)0x6b, (byte)0x1e, (byte)0x11,
                    (byte)0x5a, (byte)0xc6, (byte)0xb4, (byte)0xd8, (byte)0xa5, (byte)0x8a, (byte)0x70, (byte)0xa3,
                    (byte)0xa8, (byte)0xfa, (byte)0x05, (byte)0xd9, (byte)0x97, (byte)0x40, (byte)0xc9, (byte)0x90,
                    (byte)0x98, (byte)0x8f, (byte)0xdc, (byte)0x12, (byte)0x31, (byte)0x2c, (byte)0x47, (byte)0x6a,
                    (byte)0x99, (byte)0xae, (byte)0xc8, (byte)0x7f, (byte)0xf9, (byte)0x4f, (byte)0x5d, (byte)0x96,
                    (byte)0x6f, (byte)0xf4, (byte)0xb3, (byte)0x39, (byte)0x21, (byte)0xda, (byte)0x9c, (byte)0x85,
                    (byte)0x9e, (byte)0x3b, (byte)0xf0, (byte)0xbf, (byte)0xef, (byte)0x06, (byte)0xee, (byte)0xe5,
                    (byte)0x5f, (byte)0x20, (byte)0x10, (byte)0xcc, (byte)0x3c, (byte)0x54, (byte)0x4a, (byte)0x52,
                    (byte)0x94, (byte)0x0e, (byte)0xc0, (byte)0x28, (byte)0xf6, (byte)0x56, (byte)0x60, (byte)0xa2,
                    (byte)0xe3, (byte)0x0f, (byte)0xec, (byte)0x9d, (byte)0x24, (byte)0x83, (byte)0x7e, (byte)0xd5,
                    (byte)0x7c, (byte)0xeb, (byte)0x18, (byte)0xd7, (byte)0xcd, (byte)0xdd, (byte)0x78, (byte)0xff,
                    (byte)0xdb, (byte)0xa1, (byte)0x09, (byte)0xd0, (byte)0x76, (byte)0x84, (byte)0x75, (byte)0xbb,
                    (byte)0x1d, (byte)0x1a, (byte)0x2f, (byte)0xb0, (byte)0xfe, (byte)0xd6, (byte)0x34, (byte)0x63,
                    (byte)0x35, (byte)0xd2, (byte)0x2a, (byte)0x59, (byte)0x6d, (byte)0x4d, (byte)0x77, (byte)0xe7,
                    (byte)0x8e, (byte)0x61, (byte)0xcf, (byte)0x9f, (byte)0xce, (byte)0x27, (byte)0xf5, (byte)0x80,
                    (byte)0x86, (byte)0xc7, (byte)0xa6, (byte)0xfb, (byte)0xf8, (byte)0x87, (byte)0xab, (byte)0x62,
                    (byte)0x3f, (byte)0xdf, (byte)0x48, (byte)0x00, (byte)0x14, (byte)0x9a, (byte)0xbd, (byte)0x5b,
                    (byte)0x04, (byte)0x92, (byte)0x02, (byte)0x25, (byte)0x65, (byte)0x4c, (byte)0x53, (byte)0x0c,
                    (byte)0xf2, (byte)0x29, (byte)0xaf, (byte)0x17, (byte)0x6c, (byte)0x41, (byte)0x30, (byte)0xe9,
                    (byte)0x93, (byte)0x55, (byte)0xf7, (byte)0xac, (byte)0x68, (byte)0x26, (byte)0xc4, (byte)0x7d,
                    (byte)0xca, (byte)0x7a, (byte)0x3e, (byte)0xa0, (byte)0x37, (byte)0x03, (byte)0xc1, (byte)0x36,
                    (byte)0x69, (byte)0x66, (byte)0x08, (byte)0x16, (byte)0xa7, (byte)0xbc, (byte)0xc5, (byte)0xd3,
                    (byte)0x22, (byte)0xb7, (byte)0x13, (byte)0x46, (byte)0x32, (byte)0xe8, (byte)0x57, (byte)0x88,
                    (byte)0x2b, (byte)0x81, (byte)0xb2, (byte)0x4e, (byte)0x64, (byte)0x1c, (byte)0xaa, (byte)0x91,
                    (byte)0x58, (byte)0x2e, (byte)0x9b, (byte)0x5c, (byte)0x1b, (byte)0x51, (byte)0x73, (byte)0x42,
                    (byte)0x23, (byte)0x01, (byte)0x6e, (byte)0xf3, (byte)0x0d, (byte)0xbe, (byte)0x3d, (byte)0x0a,
                    (byte)0x2d, (byte)0x1f, (byte)0x67, (byte)0x33, (byte)0x19, (byte)0x7b, (byte)0x5e, (byte)0xea,
                    (byte)0xde, (byte)0x8b, (byte)0xcb, (byte)0xa9, (byte)0x8c, (byte)0x8d, (byte)0xad, (byte)0x49,
                    (byte)0x82, (byte)0xe4, (byte)0xba, (byte)0xc3, (byte)0x15, (byte)0xd1, (byte)0xe0, (byte)0x89,
                    (byte)0xfc, (byte)0xb1, (byte)0xb9, (byte)0xb5, (byte)0x07, (byte)0x79, (byte)0xb8, (byte)0xe1
                },

            new byte[]
                {
                    (byte)0xb2, (byte)0xb6, (byte)0x23, (byte)0x11, (byte)0xa7, (byte)0x88, (byte)0xc5, (byte)0xa6,
                    (byte)0x39, (byte)0x8f, (byte)0xc4, (byte)0xe8, (byte)0x73, (byte)0x22, (byte)0x43, (byte)0xc3,
                    (byte)0x82, (byte)0x27, (byte)0xcd, (byte)0x18, (byte)0x51, (byte)0x62, (byte)0x2d, (byte)0xf7,
                    (byte)0x5c, (byte)0x0e, (byte)0x3b, (byte)0xfd, (byte)0xca, (byte)0x9b, (byte)0x0d, (byte)0x0f,
                    (byte)0x79, (byte)0x8c, (byte)0x10, (byte)0x4c, (byte)0x74, (byte)0x1c, (byte)0x0a, (byte)0x8e,
                    (byte)0x7c, (byte)0x94, (byte)0x07, (byte)0xc7, (byte)0x5e, (byte)0x14, (byte)0xa1, (byte)0x21,
                    (byte)0x57, (byte)0x50, (byte)0x4e, (byte)0xa9, (byte)0x80, (byte)0xd9, (byte)0xef, (byte)0x64,
                    (byte)0x41, (byte)0xcf, (byte)0x3c, (byte)0xee, (byte)0x2e, (byte)0x13, (byte)0x29, (byte)0xba,
                    (byte)0x34, (byte)0x5a, (byte)0xae, (byte)0x8a, (byte)0x61, (byte)0x33, (byte)0x12, (byte)0xb9,
                    (byte)0x55, (byte)0xa8, (byte)0x15, (byte)0x05, (byte)0xf6, (byte)0x03, (byte)0x06, (byte)0x49,
                    (byte)0xb5, (byte)0x25, (byte)0x09, (byte)0x16, (byte)0x0c, (byte)0x2a, (byte)0x38, (byte)0xfc,
                    (byte)0x20, (byte)0xf4, (byte)0xe5, (byte)0x7f, (byte)0xd7, (byte)0x31, (byte)0x2b, (byte)0x66,
                    (byte)0x6f, (byte)0xff, (byte)0x72, (byte)0x86, (byte)0xf0, (byte)0xa3, (byte)0x2f, (byte)0x78,
                    (byte)0x00, (byte)0xbc, (byte)0xcc, (byte)0xe2, (byte)0xb0, (byte)0xf1, (byte)0x42, (byte)0xb4,
                    (byte)0x30, (byte)0x5f, (byte)0x60, (byte)0x04, (byte)0xec, (byte)0xa5, (byte)0xe3, (byte)0x8b,
                    (byte)0xe7, (byte)0x1d, (byte)0xbf, (byte)0x84, (byte)0x7b, (byte)0xe6, (byte)0x81, (byte)0xf8,
                    (byte)0xde, (byte)0xd8, (byte)0xd2, (byte)0x17, (byte)0xce, (byte)0x4b, (byte)0x47, (byte)0xd6,
                    (byte)0x69, (byte)0x6c, (byte)0x19, (byte)0x99, (byte)0x9a, (byte)0x01, (byte)0xb3, (byte)0x85,
                    (byte)0xb1, (byte)0xf9, (byte)0x59, (byte)0xc2, (byte)0x37, (byte)0xe9, (byte)0xc8, (byte)0xa0,
                    (byte)0xed, (byte)0x4f, (byte)0x89, (byte)0x68, (byte)0x6d, (byte)0xd5, (byte)0x26, (byte)0x91,
                    (byte)0x87, (byte)0x58, (byte)0xbd, (byte)0xc9, (byte)0x98, (byte)0xdc, (byte)0x75, (byte)0xc0,
                    (byte)0x76, (byte)0xf5, (byte)0x67, (byte)0x6b, (byte)0x7e, (byte)0xeb, (byte)0x52, (byte)0xcb,
                    (byte)0xd1, (byte)0x5b, (byte)0x9f, (byte)0x0b, (byte)0xdb, (byte)0x40, (byte)0x92, (byte)0x1a,
                    (byte)0xfa, (byte)0xac, (byte)0xe4, (byte)0xe1, (byte)0x71, (byte)0x1f, (byte)0x65, (byte)0x8d,
                    (byte)0x97, (byte)0x9e, (byte)0x95, (byte)0x90, (byte)0x5d, (byte)0xb7, (byte)0xc1, (byte)0xaf,
                    (byte)0x54, (byte)0xfb, (byte)0x02, (byte)0xe0, (byte)0x35, (byte)0xbb, (byte)0x3a, (byte)0x4d,
                    (byte)0xad, (byte)0x2c, (byte)0x3d, (byte)0x56, (byte)0x08, (byte)0x1b, (byte)0x4a, (byte)0x93,
                    (byte)0x6a, (byte)0xab, (byte)0xb8, (byte)0x7a, (byte)0xf2, (byte)0x7d, (byte)0xda, (byte)0x3f,
                    (byte)0xfe, (byte)0x3e, (byte)0xbe, (byte)0xea, (byte)0xaa, (byte)0x44, (byte)0xc6, (byte)0xd0,
                    (byte)0x36, (byte)0x48, (byte)0x70, (byte)0x96, (byte)0x77, (byte)0x24, (byte)0x53, (byte)0xdf,
                    (byte)0xf3, (byte)0x83, (byte)0x28, (byte)0x32, (byte)0x45, (byte)0x1e, (byte)0xa4, (byte)0xd3,
                    (byte)0xa2, (byte)0x46, (byte)0x6e, (byte)0x9c, (byte)0xdd, (byte)0x63, (byte)0xd4, (byte)0x9d
                }
        };

//endregion

}
