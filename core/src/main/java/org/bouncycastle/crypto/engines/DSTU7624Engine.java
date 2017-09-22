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
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        if (!(params instanceof KeyParameter))
        {
            throw new IllegalArgumentException("Invalid parameter passed to DSTU7624Engine init");
        }

        this.forEncryption = forEncryption;

        byte[] keyBytes = ((KeyParameter)params).getKey();
        int keyBitLength = keyBytes.length * BITS_IN_BYTE;
        int blockBitLength = wordsInBlock * BITS_IN_WORD;

        if (keyBitLength != 128 && keyBitLength != 256 && keyBitLength != 512)
        {
            throw new IllegalArgumentException("unsupported key length: only 128/256/512 are allowed");
        }

        /* Limitations on key lengths depending on block lengths. See table 6.1 in standard */
        if (keyBitLength != blockBitLength && keyBitLength != (2 * blockBitLength))
        {
            throw new IllegalArgumentException("Unsupported key length");
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

        if (keyBytes.length != (keyBitLength >>> 3))
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

    public String getAlgorithmName()
    {
        return "DSTU7624";
    }

    public int getBlockSize()
    {
        return wordsInBlock << 3;
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

        /* Unpack */
        Pack.littleEndianToLong(in, inOff, internalState);

        if (forEncryption)
        {
            /* Encrypt */

            addRoundKey(0);

            for (int round = 0;;)
            {
                subBytes();
                shiftRows();
                mixColumns();

                if (++round == roundsAmount)
                {
                    break;
                }

                xorRoundKey(round);
            }

            addRoundKey(roundsAmount);
        }
        else
        {
            /* Decrypt */

            subRoundKey(roundsAmount);

            for (int round = roundsAmount;;)
            {
                invMixColumns();
                invShiftRows();
                invSubBytes();

                if (--round == 0)
                {
                    break;
                }

                xorRoundKey(round);
            }

            subRoundKey(0);
        }

        /* Pack */
        Pack.longToLittleEndian(internalState, out, outOff);

        return getBlockSize();
    }

    public void reset()
    {
        Arrays.fill(internalState, 0);
    }

    private void addRoundKey(int round)
    {
        long[] roundKey = roundKeys[round];
        for (int i = 0; i < wordsInBlock; ++i)
        {
            internalState[i] += roundKey[i];
        }
    }

    private void subRoundKey(int round)
    {
        long[] roundKey = roundKeys[round];
        for (int i = 0; i < wordsInBlock; ++i)
        {
            internalState[i] -= roundKey[i];
        }
    }

    private void xorRoundKey(int round)
    {
        long[] roundKey = roundKeys[round];
        for (int i = 0; i < wordsInBlock; ++i)
        {
            internalState[i] ^= roundKey[i];
        }
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

        subBytes();
        shiftRows();
        mixColumns();

        for (int wordIndex = 0; wordIndex < internalState.length; wordIndex++)
        {
            internalState[wordIndex] ^= k1[wordIndex];
        }

        subBytes();
        shiftRows();
        mixColumns();

        for (int wordIndex = 0; wordIndex < internalState.length; wordIndex++)
        {
            internalState[wordIndex] += k0[wordIndex];
        }

        subBytes();
        shiftRows();
        mixColumns();

        System.arraycopy(internalState, 0, tempKeys, 0, wordsInBlock);
    }

    private void workingKeyExpandEven(long[] workingKey, long[] tempKey)
    {
        long[] initialData = new long[wordsInKey];
        long[] tempRoundKey = new long[wordsInBlock];

        int round = 0;

        System.arraycopy(workingKey, 0, initialData, 0, wordsInKey);

        long tmv = 0x0001000100010001L;

        while (true)
        {
            for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
            {
                tempRoundKey[wordIndex] = tempKey[wordIndex] + tmv;
            }

            for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
            {
                internalState[wordIndex] = initialData[wordIndex] + tempRoundKey[wordIndex];
            }

            subBytes();
            shiftRows();
            mixColumns();

            for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
            {
                internalState[wordIndex] ^= tempRoundKey[wordIndex];
            }

            subBytes();
            shiftRows();
            mixColumns();

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
                tmv <<= 1;

                for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
                {
                    tempRoundKey[wordIndex] = tempKey[wordIndex] + tmv;
                }

                for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
                {
                    internalState[wordIndex] = initialData[wordsInBlock + wordIndex] + tempRoundKey[wordIndex];
                }

                subBytes();
                shiftRows();
                mixColumns();

                for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
                {
                    internalState[wordIndex] ^= tempRoundKey[wordIndex];
                }

                subBytes();
                shiftRows();
                mixColumns();

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
            tmv <<= 1;

            long temp = initialData[0];
            for (int i = 1; i < initialData.length; ++i)
            {
                initialData[i - 1] = initialData[i];
            }
            initialData[initialData.length - 1] = temp;
        }
    }

    private void workingKeyExpandOdd()
    {
        for (int roundIndex = 1; roundIndex < roundsAmount; roundIndex += 2)
        {
            rotateLeft(roundKeys[roundIndex - 1], roundKeys[roundIndex]);
        }
    }

    private void subBytes()
    {
        byte[] s0 = sboxesForEncryption[0];
        byte[] s1 = sboxesForEncryption[1];
        byte[] s2 = sboxesForEncryption[2];
        byte[] s3 = sboxesForEncryption[3];

        for (int i = 0; i < wordsInBlock; i++)
        {
            long u = internalState[i];
            int lo = (int)u, hi = (int)(u >>> 32);
            byte t0 = s0[lo & 0xFF];
            byte t1 = s1[(lo >>> 8) & 0xFF];
            byte t2 = s2[(lo >>> 16) & 0xFF];
            byte t3 = s3[lo >>> 24];
            lo = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | ((int)t3 << 24);
            byte t4 = s0[hi & 0xFF];
            byte t5 = s1[(hi >>> 8) & 0xFF];
            byte t6 = s2[(hi >>> 16) & 0xFF];
            byte t7 = s3[hi >>> 24];
            hi = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | ((int)t7 << 24);
            internalState[i] = (lo & 0xFFFFFFFFL) | ((long)hi << 32);
        }
    }

    private void invSubBytes()
    {
        byte[] s0 = sboxesForDecryption[0];
        byte[] s1 = sboxesForDecryption[1];
        byte[] s2 = sboxesForDecryption[2];
        byte[] s3 = sboxesForDecryption[3];

        for (int i = 0; i < wordsInBlock; i++)
        {
            long u = internalState[i];
            int lo = (int)u, hi = (int)(u >>> 32);
            byte t0 = s0[lo & 0xFF];
            byte t1 = s1[(lo >>> 8) & 0xFF];
            byte t2 = s2[(lo >>> 16) & 0xFF];
            byte t3 = s3[lo >>> 24];
            lo = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | ((int)t3 << 24);
            byte t4 = s0[hi & 0xFF];
            byte t5 = s1[(hi >>> 8) & 0xFF];
            byte t6 = s2[(hi >>> 16) & 0xFF];
            byte t7 = s3[hi >>> 24];
            hi = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | ((int)t7 << 24);
            internalState[i] = (lo & 0xFFFFFFFFL) | ((long)hi << 32);
        }
    }

    private void shiftRows()
    {
        switch (wordsInBlock)
        {
        case 2:
        {
            long c0 = internalState[0], c1 = internalState[1];
            internalState[0] = (c0 & 0x00000000FFFFFFFFL) | (c1 & 0xFFFFFFFF00000000L);
            internalState[1] = (c1 & 0x00000000FFFFFFFFL) | (c0 & 0xFFFFFFFF00000000L);
            break;
        }
        case 4:
        {
            long c0 = internalState[0], c1 = internalState[1], c2 = internalState[2], c3 = internalState[3];
            internalState[0] = (c0 & 0x000000000000FFFFL) | (c3 & 0x00000000FFFF0000L) | (c2 & 0x0000FFFF00000000L) | (c1 & 0xFFFF000000000000L);
            internalState[1] = (c1 & 0x000000000000FFFFL) | (c0 & 0x00000000FFFF0000L) | (c3 & 0x0000FFFF00000000L) | (c2 & 0xFFFF000000000000L);
            internalState[2] = (c2 & 0x000000000000FFFFL) | (c1 & 0x00000000FFFF0000L) | (c0 & 0x0000FFFF00000000L) | (c3 & 0xFFFF000000000000L);
            internalState[3] = (c3 & 0x000000000000FFFFL) | (c2 & 0x00000000FFFF0000L) | (c1 & 0x0000FFFF00000000L) | (c0 & 0xFFFF000000000000L);
            break;
        }
        case 8:
        {
            long c0 = internalState[0], c1 = internalState[1], c2 = internalState[2], c3 = internalState[3];
            long c4 = internalState[4], c5 = internalState[5], c6 = internalState[6], c7 = internalState[7];
            internalState[0] = (c0 & 0x00000000000000FFL) | (c7 & 0x000000000000FF00L) | (c6 & 0x0000000000FF0000L) | (c5 & 0x00000000FF000000L)
                             | (c4 & 0x000000FF00000000L) | (c3 & 0x0000FF0000000000L) | (c2 & 0x00FF000000000000L) | (c1 & 0xFF00000000000000L);
            internalState[1] = (c1 & 0x00000000000000FFL) | (c0 & 0x000000000000FF00L) | (c7 & 0x0000000000FF0000L) | (c6 & 0x00000000FF000000L)
                             | (c5 & 0x000000FF00000000L) | (c4 & 0x0000FF0000000000L) | (c3 & 0x00FF000000000000L) | (c2 & 0xFF00000000000000L);
            internalState[2] = (c2 & 0x00000000000000FFL) | (c1 & 0x000000000000FF00L) | (c0 & 0x0000000000FF0000L) | (c7 & 0x00000000FF000000L)
                             | (c6 & 0x000000FF00000000L) | (c5 & 0x0000FF0000000000L) | (c4 & 0x00FF000000000000L) | (c3 & 0xFF00000000000000L);
            internalState[3] = (c3 & 0x00000000000000FFL) | (c2 & 0x000000000000FF00L) | (c1 & 0x0000000000FF0000L) | (c0 & 0x00000000FF000000L)
                             | (c7 & 0x000000FF00000000L) | (c6 & 0x0000FF0000000000L) | (c5 & 0x00FF000000000000L) | (c4 & 0xFF00000000000000L);
            internalState[4] = (c4 & 0x00000000000000FFL) | (c3 & 0x000000000000FF00L) | (c2 & 0x0000000000FF0000L) | (c1 & 0x00000000FF000000L)
                             | (c0 & 0x000000FF00000000L) | (c7 & 0x0000FF0000000000L) | (c6 & 0x00FF000000000000L) | (c5 & 0xFF00000000000000L);
            internalState[5] = (c5 & 0x00000000000000FFL) | (c4 & 0x000000000000FF00L) | (c3 & 0x0000000000FF0000L) | (c2 & 0x00000000FF000000L)
                             | (c1 & 0x000000FF00000000L) | (c0 & 0x0000FF0000000000L) | (c7 & 0x00FF000000000000L) | (c6 & 0xFF00000000000000L);
            internalState[6] = (c6 & 0x00000000000000FFL) | (c5 & 0x000000000000FF00L) | (c4 & 0x0000000000FF0000L) | (c3 & 0x00000000FF000000L)
                             | (c2 & 0x000000FF00000000L) | (c1 & 0x0000FF0000000000L) | (c0 & 0x00FF000000000000L) | (c7 & 0xFF00000000000000L);
            internalState[7] = (c7 & 0x00000000000000FFL) | (c6 & 0x000000000000FF00L) | (c5 & 0x0000000000FF0000L) | (c4 & 0x00000000FF000000L)
                             | (c3 & 0x000000FF00000000L) | (c2 & 0x0000FF0000000000L) | (c1 & 0x00FF000000000000L) | (c0 & 0xFF00000000000000L);
            break;
        }
        default:
        {
            throw new IllegalStateException("unsupported block length: only 128/256/512 are allowed");
        }
        }
    }

    private void invShiftRows()
    {
        switch (wordsInBlock)
        {
        case 2:
        {
            long c0 = internalState[0], c1 = internalState[1];
            internalState[0] = (c0 & 0x00000000FFFFFFFFL) | (c1 & 0xFFFFFFFF00000000L);
            internalState[1] = (c1 & 0x00000000FFFFFFFFL) | (c0 & 0xFFFFFFFF00000000L);
            break;
        }
        case 4:
        {
            long c0 = internalState[0], c1 = internalState[1], c2 = internalState[2], c3 = internalState[3];
            internalState[0] = (c0 & 0x000000000000FFFFL) | (c1 & 0x00000000FFFF0000L) | (c2 & 0x0000FFFF00000000L) | (c3 & 0xFFFF000000000000L);
            internalState[1] = (c1 & 0x000000000000FFFFL) | (c2 & 0x00000000FFFF0000L) | (c3 & 0x0000FFFF00000000L) | (c0 & 0xFFFF000000000000L);
            internalState[2] = (c2 & 0x000000000000FFFFL) | (c3 & 0x00000000FFFF0000L) | (c0 & 0x0000FFFF00000000L) | (c1 & 0xFFFF000000000000L);
            internalState[3] = (c3 & 0x000000000000FFFFL) | (c0 & 0x00000000FFFF0000L) | (c1 & 0x0000FFFF00000000L) | (c2 & 0xFFFF000000000000L);
            break;
        }
        case 8:
        {
            long c0 = internalState[0], c1 = internalState[1], c2 = internalState[2], c3 = internalState[3];
            long c4 = internalState[4], c5 = internalState[5], c6 = internalState[6], c7 = internalState[7];
            internalState[0] = (c0 & 0x00000000000000FFL) | (c1 & 0x000000000000FF00L) | (c2 & 0x0000000000FF0000L) | (c3 & 0x00000000FF000000L)
                             | (c4 & 0x000000FF00000000L) | (c5 & 0x0000FF0000000000L) | (c6 & 0x00FF000000000000L) | (c7 & 0xFF00000000000000L);
            internalState[1] = (c1 & 0x00000000000000FFL) | (c2 & 0x000000000000FF00L) | (c3 & 0x0000000000FF0000L) | (c4 & 0x00000000FF000000L)
                             | (c5 & 0x000000FF00000000L) | (c6 & 0x0000FF0000000000L) | (c7 & 0x00FF000000000000L) | (c0 & 0xFF00000000000000L);
            internalState[2] = (c2 & 0x00000000000000FFL) | (c3 & 0x000000000000FF00L) | (c4 & 0x0000000000FF0000L) | (c5 & 0x00000000FF000000L)
                             | (c6 & 0x000000FF00000000L) | (c7 & 0x0000FF0000000000L) | (c0 & 0x00FF000000000000L) | (c1 & 0xFF00000000000000L);
            internalState[3] = (c3 & 0x00000000000000FFL) | (c4 & 0x000000000000FF00L) | (c5 & 0x0000000000FF0000L) | (c6 & 0x00000000FF000000L)
                             | (c7 & 0x000000FF00000000L) | (c0 & 0x0000FF0000000000L) | (c1 & 0x00FF000000000000L) | (c2 & 0xFF00000000000000L);
            internalState[4] = (c4 & 0x00000000000000FFL) | (c5 & 0x000000000000FF00L) | (c6 & 0x0000000000FF0000L) | (c7 & 0x00000000FF000000L)
                             | (c0 & 0x000000FF00000000L) | (c1 & 0x0000FF0000000000L) | (c2 & 0x00FF000000000000L) | (c3 & 0xFF00000000000000L);
            internalState[5] = (c5 & 0x00000000000000FFL) | (c6 & 0x000000000000FF00L) | (c7 & 0x0000000000FF0000L) | (c0 & 0x00000000FF000000L)
                             | (c1 & 0x000000FF00000000L) | (c2 & 0x0000FF0000000000L) | (c3 & 0x00FF000000000000L) | (c4 & 0xFF00000000000000L);
            internalState[6] = (c6 & 0x00000000000000FFL) | (c7 & 0x000000000000FF00L) | (c0 & 0x0000000000FF0000L) | (c1 & 0x00000000FF000000L)
                             | (c2 & 0x000000FF00000000L) | (c3 & 0x0000FF0000000000L) | (c4 & 0x00FF000000000000L) | (c5 & 0xFF00000000000000L);
            internalState[7] = (c7 & 0x00000000000000FFL) | (c0 & 0x000000000000FF00L) | (c1 & 0x0000000000FF0000L) | (c2 & 0x00000000FF000000L)
                             | (c3 & 0x000000FF00000000L) | (c4 & 0x0000FF0000000000L) | (c5 & 0x00FF000000000000L) | (c6 & 0xFF00000000000000L);
            break;
        }
        default:
        {
            throw new IllegalStateException("unsupported block length: only 128/256/512 are allowed");
        }
        }
    }

    private long mixColumn(long colVal)
    {
//        long rowMatrix = mdsMatrix;
//
//        long result = 0;
//        for (int row = 7; row >= 0; --row)
//        {
//            rowMatrix = (rowMatrix >>> 8) | (rowMatrix << 56);
//
//            // mdsMatrix elements have maximum degree of 3
//            long product = multiplyGFx8(colVal, rowMatrix, 3);
//
//            product ^= (product >>> 32);
//            product ^= (product >>> 16);
//            product ^= (product >>> 8);
//
//            result <<= 8;
//            result |= (product & 0xFFL);
//        }
//
//        return result;

        long t0 = multiplyGFx8(colVal, mdsMatrix, 3);
        long t1 = multiplyGFx8(colVal, (mdsMatrix <<  8) | (mdsMatrix >>> 56), 3);
        long t2 = multiplyGFx8(colVal, (mdsMatrix << 16) | (mdsMatrix >>> 48), 3);
        long t3 = multiplyGFx8(colVal, (mdsMatrix << 24) | (mdsMatrix >>> 40), 3);
        long t4 = multiplyGFx8(colVal, (mdsMatrix << 32) | (mdsMatrix >>> 32), 3);
        long t5 = multiplyGFx8(colVal, (mdsMatrix << 40) | (mdsMatrix >>> 24), 3);
        long t6 = multiplyGFx8(colVal, (mdsMatrix << 48) | (mdsMatrix >>> 16), 3);
        long t7 = multiplyGFx8(colVal, (mdsMatrix << 56) | (mdsMatrix >>> 8), 3);

        long t04 = ((t0 ^ (t0 >>> 32)) & 0x00000000FFFFFFFFL) | ((t4 ^ (t4 << 32)) & 0xFFFFFFFF00000000L); 
        long t15 = ((t1 ^ (t1 >>> 32)) & 0x00000000FFFFFFFFL) | ((t5 ^ (t5 << 32)) & 0xFFFFFFFF00000000L); 
        long t26 = ((t2 ^ (t2 >>> 32)) & 0x00000000FFFFFFFFL) | ((t6 ^ (t6 << 32)) & 0xFFFFFFFF00000000L); 
        long t37 = ((t3 ^ (t3 >>> 32)) & 0x00000000FFFFFFFFL) | ((t7 ^ (t7 << 32)) & 0xFFFFFFFF00000000L); 

        long t0246 = ((t04 ^ (t04 >>> 16)) & 0x0000FFFF0000FFFFL) | ((t26 ^ (t26 << 16)) & 0xFFFF0000FFFF0000L);
        long t1357 = ((t15 ^ (t15 >>> 16)) & 0x0000FFFF0000FFFFL) | ((t37 ^ (t37 << 16)) & 0xFFFF0000FFFF0000L);

        return (t0246 ^ (t0246 >>> 8)) & 0x00FF00FF00FF00FFL
            |  (t1357 ^ (t1357 <<  8)) & 0xFF00FF00FF00FF00L;
    }

    private void mixColumns()
    {
        for (int col = 0; col < wordsInBlock; ++col)
        {
            internalState[col] = mixColumn(internalState[col]);
        }
    }

    private long invMixColumn(long colVal)
    {
//        long rowMatrix = mdsInvMatrix;
//
//        long result = 0;
//        for (int row = 7; row >= 0; --row)
//        {
//            rowMatrix = (rowMatrix >>> 8) | (rowMatrix << 56);
//
//            long product = multiplyGFx8(colVal, rowMatrix, 7);
//
//            product ^= (product >>> 32);
//            product ^= (product >>> 16);
//            product ^= (product >>> 8);
//
//            result <<= 8;
//            result |= (product & 0xFFL);
//        }
//
//        return result;

        long t0 = multiplyGFx8(colVal, mdsInvMatrix, 7);
        long t1 = multiplyGFx8(colVal, (mdsInvMatrix <<  8) | (mdsInvMatrix >>> 56), 7);
        long t2 = multiplyGFx8(colVal, (mdsInvMatrix << 16) | (mdsInvMatrix >>> 48), 7);
        long t3 = multiplyGFx8(colVal, (mdsInvMatrix << 24) | (mdsInvMatrix >>> 40), 7);
        long t4 = multiplyGFx8(colVal, (mdsInvMatrix << 32) | (mdsInvMatrix >>> 32), 7);
        long t5 = multiplyGFx8(colVal, (mdsInvMatrix << 40) | (mdsInvMatrix >>> 24), 7);
        long t6 = multiplyGFx8(colVal, (mdsInvMatrix << 48) | (mdsInvMatrix >>> 16), 7);
        long t7 = multiplyGFx8(colVal, (mdsInvMatrix << 56) | (mdsInvMatrix >>> 8), 7);

        long t04 = ((t0 ^ (t0 >>> 32)) & 0x00000000FFFFFFFFL) | ((t4 ^ (t4 << 32)) & 0xFFFFFFFF00000000L); 
        long t15 = ((t1 ^ (t1 >>> 32)) & 0x00000000FFFFFFFFL) | ((t5 ^ (t5 << 32)) & 0xFFFFFFFF00000000L); 
        long t26 = ((t2 ^ (t2 >>> 32)) & 0x00000000FFFFFFFFL) | ((t6 ^ (t6 << 32)) & 0xFFFFFFFF00000000L); 
        long t37 = ((t3 ^ (t3 >>> 32)) & 0x00000000FFFFFFFFL) | ((t7 ^ (t7 << 32)) & 0xFFFFFFFF00000000L); 

        long t0246 = ((t04 ^ (t04 >>> 16)) & 0x0000FFFF0000FFFFL) | ((t26 ^ (t26 << 16)) & 0xFFFF0000FFFF0000L);
        long t1357 = ((t15 ^ (t15 >>> 16)) & 0x0000FFFF0000FFFFL) | ((t37 ^ (t37 << 16)) & 0xFFFF0000FFFF0000L);

        return (t0246 ^ (t0246 >>> 8)) & 0x00FF00FF00FF00FFL
            |  (t1357 ^ (t1357 <<  8)) & 0xFF00FF00FF00FF00L;
    }

    private void invMixColumns()
    {
        for (int col = 0; col < wordsInBlock; ++col)
        {
            internalState[col] = invMixColumn(internalState[col]);
        }
    }

    /*
     * Pair-wise modular multiplication of 8 byte-pairs.
     * 
     * REDUCTION_POLYNOMIAL is x^8 + x^4 + x^3 + x^2 + 1
     */  
    private static long multiplyGFx8(long u, long v, int vMaxDegree)
    {
        long r = u & ((v & 0x0101010101010101L) * 0xFFL);

        for (int i = 1; i <= vMaxDegree; ++i)
        {
            u = ((u & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((u >>> 7) & 0x0101010101010101L) * 0x1DL);
            v >>>= 1;

            r ^= u & ((v & 0x0101010101010101L) * 0xFFL);
        }

        return r;
    }

//    private static long multiplyMDS(long u)
//    {
//        long r = 0, s = 0, t = (u >>> 8);
//        r ^= u & 0x0000001F00000000L; r <<= 1;
//        s ^= t & 0x00000000E0000000L; s <<= 1;
//        r ^= u & 0x3F3F3F00003F0000L; r <<= 1;
//        s ^= t & 0x00C0C0C00000C000L; s <<= 1;
//        r ^= u & 0x007F7F0000000000L; r <<= 1;
//        s ^= t & 0x0000808000000000L; s <<= 1;
//        r ^= u & 0x00FF0000FFFFFFFFL;
//        r ^= s ^ (s << 2) ^ (s << 3) ^ (s << 4);
//        return r;
//    }

    private void rotateLeft(long[] x, long[] z)
    {
        switch (wordsInBlock)
        {
        case 2:
        {
            long x0 = x[0], x1 = x[1];
            z[0] = (x0 >>> 56) | (x1 << 8);
            z[1] = (x1 >>> 56) | (x0 << 8);
            break;
        }
        case 4:
        {
            long x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
            z[0] = (x1 >>> 24) | (x2 << 40);
            z[1] = (x2 >>> 24) | (x3 << 40);
            z[2] = (x3 >>> 24) | (x0 << 40);
            z[3] = (x0 >>> 24) | (x1 << 40);
            break;
        }
        case 8:
        {
            long x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
            long x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
            z[0] = (x2 >>> 24) | (x3 << 40);
            z[1] = (x3 >>> 24) | (x4 << 40);
            z[2] = (x4 >>> 24) | (x5 << 40);
            z[3] = (x5 >>> 24) | (x6 << 40);
            z[4] = (x6 >>> 24) | (x7 << 40);
            z[5] = (x7 >>> 24) | (x0 << 40);
            z[6] = (x0 >>> 24) | (x1 << 40);
            z[7] = (x1 >>> 24) | (x2 << 40);
            break;
        }
        default:
        {
            throw new IllegalStateException("unsupported block length: only 128/256/512 are allowed");
        }
        }
    }

    private static final long mdsMatrix = 0x0407060801050101L;
    private static final long mdsInvMatrix = 0xCAD7492FA87695ADL;

    private byte[][] sboxesForEncryption = {
        new byte[]{ (byte)0xa8, (byte)0x43, (byte)0x5f, (byte)0x06, (byte)0x6b, (byte)0x75, (byte)0x6c, (byte)0x59,
            (byte)0x71, (byte)0xdf, (byte)0x87, (byte)0x95, (byte)0x17, (byte)0xf0, (byte)0xd8, (byte)0x09, (byte)0x6d,
            (byte)0xf3, (byte)0x1d, (byte)0xcb, (byte)0xc9, (byte)0x4d, (byte)0x2c, (byte)0xaf, (byte)0x79, (byte)0xe0,
            (byte)0x97, (byte)0xfd, (byte)0x6f, (byte)0x4b, (byte)0x45, (byte)0x39, (byte)0x3e, (byte)0xdd, (byte)0xa3,
            (byte)0x4f, (byte)0xb4, (byte)0xb6, (byte)0x9a, (byte)0x0e, (byte)0x1f, (byte)0xbf, (byte)0x15, (byte)0xe1,
            (byte)0x49, (byte)0xd2, (byte)0x93, (byte)0xc6, (byte)0x92, (byte)0x72, (byte)0x9e, (byte)0x61, (byte)0xd1,
            (byte)0x63, (byte)0xfa, (byte)0xee, (byte)0xf4, (byte)0x19, (byte)0xd5, (byte)0xad, (byte)0x58, (byte)0xa4,
            (byte)0xbb, (byte)0xa1, (byte)0xdc, (byte)0xf2, (byte)0x83, (byte)0x37, (byte)0x42, (byte)0xe4, (byte)0x7a,
            (byte)0x32, (byte)0x9c, (byte)0xcc, (byte)0xab, (byte)0x4a, (byte)0x8f, (byte)0x6e, (byte)0x04, (byte)0x27,
            (byte)0x2e, (byte)0xe7, (byte)0xe2, (byte)0x5a, (byte)0x96, (byte)0x16, (byte)0x23, (byte)0x2b, (byte)0xc2,
            (byte)0x65, (byte)0x66, (byte)0x0f, (byte)0xbc, (byte)0xa9, (byte)0x47, (byte)0x41, (byte)0x34, (byte)0x48,
            (byte)0xfc, (byte)0xb7, (byte)0x6a, (byte)0x88, (byte)0xa5, (byte)0x53, (byte)0x86, (byte)0xf9, (byte)0x5b,
            (byte)0xdb, (byte)0x38, (byte)0x7b, (byte)0xc3, (byte)0x1e, (byte)0x22, (byte)0x33, (byte)0x24, (byte)0x28,
            (byte)0x36, (byte)0xc7, (byte)0xb2, (byte)0x3b, (byte)0x8e, (byte)0x77, (byte)0xba, (byte)0xf5, (byte)0x14,
            (byte)0x9f, (byte)0x08, (byte)0x55, (byte)0x9b, (byte)0x4c, (byte)0xfe, (byte)0x60, (byte)0x5c, (byte)0xda,
            (byte)0x18, (byte)0x46, (byte)0xcd, (byte)0x7d, (byte)0x21, (byte)0xb0, (byte)0x3f, (byte)0x1b, (byte)0x89,
            (byte)0xff, (byte)0xeb, (byte)0x84, (byte)0x69, (byte)0x3a, (byte)0x9d, (byte)0xd7, (byte)0xd3, (byte)0x70,
            (byte)0x67, (byte)0x40, (byte)0xb5, (byte)0xde, (byte)0x5d, (byte)0x30, (byte)0x91, (byte)0xb1, (byte)0x78,
            (byte)0x11, (byte)0x01, (byte)0xe5, (byte)0x00, (byte)0x68, (byte)0x98, (byte)0xa0, (byte)0xc5, (byte)0x02,
            (byte)0xa6, (byte)0x74, (byte)0x2d, (byte)0x0b, (byte)0xa2, (byte)0x76, (byte)0xb3, (byte)0xbe, (byte)0xce,
            (byte)0xbd, (byte)0xae, (byte)0xe9, (byte)0x8a, (byte)0x31, (byte)0x1c, (byte)0xec, (byte)0xf1, (byte)0x99,
            (byte)0x94, (byte)0xaa, (byte)0xf6, (byte)0x26, (byte)0x2f, (byte)0xef, (byte)0xe8, (byte)0x8c, (byte)0x35,
            (byte)0x03, (byte)0xd4, (byte)0x7f, (byte)0xfb, (byte)0x05, (byte)0xc1, (byte)0x5e, (byte)0x90, (byte)0x20,
            (byte)0x3d, (byte)0x82, (byte)0xf7, (byte)0xea, (byte)0x0a, (byte)0x0d, (byte)0x7e, (byte)0xf8, (byte)0x50,
            (byte)0x1a, (byte)0xc4, (byte)0x07, (byte)0x57, (byte)0xb8, (byte)0x3c, (byte)0x62, (byte)0xe3, (byte)0xc8,
            (byte)0xac, (byte)0x52, (byte)0x64, (byte)0x10, (byte)0xd0, (byte)0xd9, (byte)0x13, (byte)0x0c, (byte)0x12,
            (byte)0x29, (byte)0x51, (byte)0xb9, (byte)0xcf, (byte)0xd6, (byte)0x73, (byte)0x8d, (byte)0x81, (byte)0x54,
            (byte)0xc0, (byte)0xed, (byte)0x4e, (byte)0x44, (byte)0xa7, (byte)0x2a, (byte)0x85, (byte)0x25, (byte)0xe6,
            (byte)0xca, (byte)0x7c, (byte)0x8b, (byte)0x56, (byte)0x80 },

        new byte[]{ (byte)0xce, (byte)0xbb, (byte)0xeb, (byte)0x92, (byte)0xea, (byte)0xcb, (byte)0x13, (byte)0xc1,
            (byte)0xe9, (byte)0x3a, (byte)0xd6, (byte)0xb2, (byte)0xd2, (byte)0x90, (byte)0x17, (byte)0xf8, (byte)0x42,
            (byte)0x15, (byte)0x56, (byte)0xb4, (byte)0x65, (byte)0x1c, (byte)0x88, (byte)0x43, (byte)0xc5, (byte)0x5c,
            (byte)0x36, (byte)0xba, (byte)0xf5, (byte)0x57, (byte)0x67, (byte)0x8d, (byte)0x31, (byte)0xf6, (byte)0x64,
            (byte)0x58, (byte)0x9e, (byte)0xf4, (byte)0x22, (byte)0xaa, (byte)0x75, (byte)0x0f, (byte)0x02, (byte)0xb1,
            (byte)0xdf, (byte)0x6d, (byte)0x73, (byte)0x4d, (byte)0x7c, (byte)0x26, (byte)0x2e, (byte)0xf7, (byte)0x08,
            (byte)0x5d, (byte)0x44, (byte)0x3e, (byte)0x9f, (byte)0x14, (byte)0xc8, (byte)0xae, (byte)0x54, (byte)0x10,
            (byte)0xd8, (byte)0xbc, (byte)0x1a, (byte)0x6b, (byte)0x69, (byte)0xf3, (byte)0xbd, (byte)0x33, (byte)0xab,
            (byte)0xfa, (byte)0xd1, (byte)0x9b, (byte)0x68, (byte)0x4e, (byte)0x16, (byte)0x95, (byte)0x91, (byte)0xee,
            (byte)0x4c, (byte)0x63, (byte)0x8e, (byte)0x5b, (byte)0xcc, (byte)0x3c, (byte)0x19, (byte)0xa1, (byte)0x81,
            (byte)0x49, (byte)0x7b, (byte)0xd9, (byte)0x6f, (byte)0x37, (byte)0x60, (byte)0xca, (byte)0xe7, (byte)0x2b,
            (byte)0x48, (byte)0xfd, (byte)0x96, (byte)0x45, (byte)0xfc, (byte)0x41, (byte)0x12, (byte)0x0d, (byte)0x79,
            (byte)0xe5, (byte)0x89, (byte)0x8c, (byte)0xe3, (byte)0x20, (byte)0x30, (byte)0xdc, (byte)0xb7, (byte)0x6c,
            (byte)0x4a, (byte)0xb5, (byte)0x3f, (byte)0x97, (byte)0xd4, (byte)0x62, (byte)0x2d, (byte)0x06, (byte)0xa4,
            (byte)0xa5, (byte)0x83, (byte)0x5f, (byte)0x2a, (byte)0xda, (byte)0xc9, (byte)0x00, (byte)0x7e, (byte)0xa2,
            (byte)0x55, (byte)0xbf, (byte)0x11, (byte)0xd5, (byte)0x9c, (byte)0xcf, (byte)0x0e, (byte)0x0a, (byte)0x3d,
            (byte)0x51, (byte)0x7d, (byte)0x93, (byte)0x1b, (byte)0xfe, (byte)0xc4, (byte)0x47, (byte)0x09, (byte)0x86,
            (byte)0x0b, (byte)0x8f, (byte)0x9d, (byte)0x6a, (byte)0x07, (byte)0xb9, (byte)0xb0, (byte)0x98, (byte)0x18,
            (byte)0x32, (byte)0x71, (byte)0x4b, (byte)0xef, (byte)0x3b, (byte)0x70, (byte)0xa0, (byte)0xe4, (byte)0x40,
            (byte)0xff, (byte)0xc3, (byte)0xa9, (byte)0xe6, (byte)0x78, (byte)0xf9, (byte)0x8b, (byte)0x46, (byte)0x80,
            (byte)0x1e, (byte)0x38, (byte)0xe1, (byte)0xb8, (byte)0xa8, (byte)0xe0, (byte)0x0c, (byte)0x23, (byte)0x76,
            (byte)0x1d, (byte)0x25, (byte)0x24, (byte)0x05, (byte)0xf1, (byte)0x6e, (byte)0x94, (byte)0x28, (byte)0x9a,
            (byte)0x84, (byte)0xe8, (byte)0xa3, (byte)0x4f, (byte)0x77, (byte)0xd3, (byte)0x85, (byte)0xe2, (byte)0x52,
            (byte)0xf2, (byte)0x82, (byte)0x50, (byte)0x7a, (byte)0x2f, (byte)0x74, (byte)0x53, (byte)0xb3, (byte)0x61,
            (byte)0xaf, (byte)0x39, (byte)0x35, (byte)0xde, (byte)0xcd, (byte)0x1f, (byte)0x99, (byte)0xac, (byte)0xad,
            (byte)0x72, (byte)0x2c, (byte)0xdd, (byte)0xd0, (byte)0x87, (byte)0xbe, (byte)0x5e, (byte)0xa6, (byte)0xec,
            (byte)0x04, (byte)0xc6, (byte)0x03, (byte)0x34, (byte)0xfb, (byte)0xdb, (byte)0x59, (byte)0xb6, (byte)0xc2,
            (byte)0x01, (byte)0xf0, (byte)0x5a, (byte)0xed, (byte)0xa7, (byte)0x66, (byte)0x21, (byte)0x7f, (byte)0x8a,
            (byte)0x27, (byte)0xc7, (byte)0xc0, (byte)0x29, (byte)0xd7 },

        new byte[]{ (byte)0x93, (byte)0xd9, (byte)0x9a, (byte)0xb5, (byte)0x98, (byte)0x22, (byte)0x45, (byte)0xfc,
            (byte)0xba, (byte)0x6a, (byte)0xdf, (byte)0x02, (byte)0x9f, (byte)0xdc, (byte)0x51, (byte)0x59, (byte)0x4a,
            (byte)0x17, (byte)0x2b, (byte)0xc2, (byte)0x94, (byte)0xf4, (byte)0xbb, (byte)0xa3, (byte)0x62, (byte)0xe4,
            (byte)0x71, (byte)0xd4, (byte)0xcd, (byte)0x70, (byte)0x16, (byte)0xe1, (byte)0x49, (byte)0x3c, (byte)0xc0,
            (byte)0xd8, (byte)0x5c, (byte)0x9b, (byte)0xad, (byte)0x85, (byte)0x53, (byte)0xa1, (byte)0x7a, (byte)0xc8,
            (byte)0x2d, (byte)0xe0, (byte)0xd1, (byte)0x72, (byte)0xa6, (byte)0x2c, (byte)0xc4, (byte)0xe3, (byte)0x76,
            (byte)0x78, (byte)0xb7, (byte)0xb4, (byte)0x09, (byte)0x3b, (byte)0x0e, (byte)0x41, (byte)0x4c, (byte)0xde,
            (byte)0xb2, (byte)0x90, (byte)0x25, (byte)0xa5, (byte)0xd7, (byte)0x03, (byte)0x11, (byte)0x00, (byte)0xc3,
            (byte)0x2e, (byte)0x92, (byte)0xef, (byte)0x4e, (byte)0x12, (byte)0x9d, (byte)0x7d, (byte)0xcb, (byte)0x35,
            (byte)0x10, (byte)0xd5, (byte)0x4f, (byte)0x9e, (byte)0x4d, (byte)0xa9, (byte)0x55, (byte)0xc6, (byte)0xd0,
            (byte)0x7b, (byte)0x18, (byte)0x97, (byte)0xd3, (byte)0x36, (byte)0xe6, (byte)0x48, (byte)0x56, (byte)0x81,
            (byte)0x8f, (byte)0x77, (byte)0xcc, (byte)0x9c, (byte)0xb9, (byte)0xe2, (byte)0xac, (byte)0xb8, (byte)0x2f,
            (byte)0x15, (byte)0xa4, (byte)0x7c, (byte)0xda, (byte)0x38, (byte)0x1e, (byte)0x0b, (byte)0x05, (byte)0xd6,
            (byte)0x14, (byte)0x6e, (byte)0x6c, (byte)0x7e, (byte)0x66, (byte)0xfd, (byte)0xb1, (byte)0xe5, (byte)0x60,
            (byte)0xaf, (byte)0x5e, (byte)0x33, (byte)0x87, (byte)0xc9, (byte)0xf0, (byte)0x5d, (byte)0x6d, (byte)0x3f,
            (byte)0x88, (byte)0x8d, (byte)0xc7, (byte)0xf7, (byte)0x1d, (byte)0xe9, (byte)0xec, (byte)0xed, (byte)0x80,
            (byte)0x29, (byte)0x27, (byte)0xcf, (byte)0x99, (byte)0xa8, (byte)0x50, (byte)0x0f, (byte)0x37, (byte)0x24,
            (byte)0x28, (byte)0x30, (byte)0x95, (byte)0xd2, (byte)0x3e, (byte)0x5b, (byte)0x40, (byte)0x83, (byte)0xb3,
            (byte)0x69, (byte)0x57, (byte)0x1f, (byte)0x07, (byte)0x1c, (byte)0x8a, (byte)0xbc, (byte)0x20, (byte)0xeb,
            (byte)0xce, (byte)0x8e, (byte)0xab, (byte)0xee, (byte)0x31, (byte)0xa2, (byte)0x73, (byte)0xf9, (byte)0xca,
            (byte)0x3a, (byte)0x1a, (byte)0xfb, (byte)0x0d, (byte)0xc1, (byte)0xfe, (byte)0xfa, (byte)0xf2, (byte)0x6f,
            (byte)0xbd, (byte)0x96, (byte)0xdd, (byte)0x43, (byte)0x52, (byte)0xb6, (byte)0x08, (byte)0xf3, (byte)0xae,
            (byte)0xbe, (byte)0x19, (byte)0x89, (byte)0x32, (byte)0x26, (byte)0xb0, (byte)0xea, (byte)0x4b, (byte)0x64,
            (byte)0x84, (byte)0x82, (byte)0x6b, (byte)0xf5, (byte)0x79, (byte)0xbf, (byte)0x01, (byte)0x5f, (byte)0x75,
            (byte)0x63, (byte)0x1b, (byte)0x23, (byte)0x3d, (byte)0x68, (byte)0x2a, (byte)0x65, (byte)0xe8, (byte)0x91,
            (byte)0xf6, (byte)0xff, (byte)0x13, (byte)0x58, (byte)0xf1, (byte)0x47, (byte)0x0a, (byte)0x7f, (byte)0xc5,
            (byte)0xa7, (byte)0xe7, (byte)0x61, (byte)0x5a, (byte)0x06, (byte)0x46, (byte)0x44, (byte)0x42, (byte)0x04,
            (byte)0xa0, (byte)0xdb, (byte)0x39, (byte)0x86, (byte)0x54, (byte)0xaa, (byte)0x8c, (byte)0x34, (byte)0x21,
            (byte)0x8b, (byte)0xf8, (byte)0x0c, (byte)0x74, (byte)0x67 },

        new byte[]{ (byte)0x68, (byte)0x8d, (byte)0xca, (byte)0x4d, (byte)0x73, (byte)0x4b, (byte)0x4e, (byte)0x2a,
            (byte)0xd4, (byte)0x52, (byte)0x26, (byte)0xb3, (byte)0x54, (byte)0x1e, (byte)0x19, (byte)0x1f, (byte)0x22,
            (byte)0x03, (byte)0x46, (byte)0x3d, (byte)0x2d, (byte)0x4a, (byte)0x53, (byte)0x83, (byte)0x13, (byte)0x8a,
            (byte)0xb7, (byte)0xd5, (byte)0x25, (byte)0x79, (byte)0xf5, (byte)0xbd, (byte)0x58, (byte)0x2f, (byte)0x0d,
            (byte)0x02, (byte)0xed, (byte)0x51, (byte)0x9e, (byte)0x11, (byte)0xf2, (byte)0x3e, (byte)0x55, (byte)0x5e,
            (byte)0xd1, (byte)0x16, (byte)0x3c, (byte)0x66, (byte)0x70, (byte)0x5d, (byte)0xf3, (byte)0x45, (byte)0x40,
            (byte)0xcc, (byte)0xe8, (byte)0x94, (byte)0x56, (byte)0x08, (byte)0xce, (byte)0x1a, (byte)0x3a, (byte)0xd2,
            (byte)0xe1, (byte)0xdf, (byte)0xb5, (byte)0x38, (byte)0x6e, (byte)0x0e, (byte)0xe5, (byte)0xf4, (byte)0xf9,
            (byte)0x86, (byte)0xe9, (byte)0x4f, (byte)0xd6, (byte)0x85, (byte)0x23, (byte)0xcf, (byte)0x32, (byte)0x99,
            (byte)0x31, (byte)0x14, (byte)0xae, (byte)0xee, (byte)0xc8, (byte)0x48, (byte)0xd3, (byte)0x30, (byte)0xa1,
            (byte)0x92, (byte)0x41, (byte)0xb1, (byte)0x18, (byte)0xc4, (byte)0x2c, (byte)0x71, (byte)0x72, (byte)0x44,
            (byte)0x15, (byte)0xfd, (byte)0x37, (byte)0xbe, (byte)0x5f, (byte)0xaa, (byte)0x9b, (byte)0x88, (byte)0xd8,
            (byte)0xab, (byte)0x89, (byte)0x9c, (byte)0xfa, (byte)0x60, (byte)0xea, (byte)0xbc, (byte)0x62, (byte)0x0c,
            (byte)0x24, (byte)0xa6, (byte)0xa8, (byte)0xec, (byte)0x67, (byte)0x20, (byte)0xdb, (byte)0x7c, (byte)0x28,
            (byte)0xdd, (byte)0xac, (byte)0x5b, (byte)0x34, (byte)0x7e, (byte)0x10, (byte)0xf1, (byte)0x7b, (byte)0x8f,
            (byte)0x63, (byte)0xa0, (byte)0x05, (byte)0x9a, (byte)0x43, (byte)0x77, (byte)0x21, (byte)0xbf, (byte)0x27,
            (byte)0x09, (byte)0xc3, (byte)0x9f, (byte)0xb6, (byte)0xd7, (byte)0x29, (byte)0xc2, (byte)0xeb, (byte)0xc0,
            (byte)0xa4, (byte)0x8b, (byte)0x8c, (byte)0x1d, (byte)0xfb, (byte)0xff, (byte)0xc1, (byte)0xb2, (byte)0x97,
            (byte)0x2e, (byte)0xf8, (byte)0x65, (byte)0xf6, (byte)0x75, (byte)0x07, (byte)0x04, (byte)0x49, (byte)0x33,
            (byte)0xe4, (byte)0xd9, (byte)0xb9, (byte)0xd0, (byte)0x42, (byte)0xc7, (byte)0x6c, (byte)0x90, (byte)0x00,
            (byte)0x8e, (byte)0x6f, (byte)0x50, (byte)0x01, (byte)0xc5, (byte)0xda, (byte)0x47, (byte)0x3f, (byte)0xcd,
            (byte)0x69, (byte)0xa2, (byte)0xe2, (byte)0x7a, (byte)0xa7, (byte)0xc6, (byte)0x93, (byte)0x0f, (byte)0x0a,
            (byte)0x06, (byte)0xe6, (byte)0x2b, (byte)0x96, (byte)0xa3, (byte)0x1c, (byte)0xaf, (byte)0x6a, (byte)0x12,
            (byte)0x84, (byte)0x39, (byte)0xe7, (byte)0xb0, (byte)0x82, (byte)0xf7, (byte)0xfe, (byte)0x9d, (byte)0x87,
            (byte)0x5c, (byte)0x81, (byte)0x35, (byte)0xde, (byte)0xb4, (byte)0xa5, (byte)0xfc, (byte)0x80, (byte)0xef,
            (byte)0xcb, (byte)0xbb, (byte)0x6b, (byte)0x76, (byte)0xba, (byte)0x5a, (byte)0x7d, (byte)0x78, (byte)0x0b,
            (byte)0x95, (byte)0xe3, (byte)0xad, (byte)0x74, (byte)0x98, (byte)0x3b, (byte)0x36, (byte)0x64, (byte)0x6d,
            (byte)0xdc, (byte)0xf0, (byte)0x59, (byte)0xa9, (byte)0x4c, (byte)0x17, (byte)0x7f, (byte)0x91, (byte)0xb8,
            (byte)0xc9, (byte)0x57, (byte)0x1b, (byte)0xe0, (byte)0x61 }

    };

    private byte[][] sboxesForDecryption = {
        new byte[]{ (byte)0xa4, (byte)0xa2, (byte)0xa9, (byte)0xc5, (byte)0x4e, (byte)0xc9, (byte)0x03, (byte)0xd9,
            (byte)0x7e, (byte)0x0f, (byte)0xd2, (byte)0xad, (byte)0xe7, (byte)0xd3, (byte)0x27, (byte)0x5b, (byte)0xe3,
            (byte)0xa1, (byte)0xe8, (byte)0xe6, (byte)0x7c, (byte)0x2a, (byte)0x55, (byte)0x0c, (byte)0x86, (byte)0x39,
            (byte)0xd7, (byte)0x8d, (byte)0xb8, (byte)0x12, (byte)0x6f, (byte)0x28, (byte)0xcd, (byte)0x8a, (byte)0x70,
            (byte)0x56, (byte)0x72, (byte)0xf9, (byte)0xbf, (byte)0x4f, (byte)0x73, (byte)0xe9, (byte)0xf7, (byte)0x57,
            (byte)0x16, (byte)0xac, (byte)0x50, (byte)0xc0, (byte)0x9d, (byte)0xb7, (byte)0x47, (byte)0x71, (byte)0x60,
            (byte)0xc4, (byte)0x74, (byte)0x43, (byte)0x6c, (byte)0x1f, (byte)0x93, (byte)0x77, (byte)0xdc, (byte)0xce,
            (byte)0x20, (byte)0x8c, (byte)0x99, (byte)0x5f, (byte)0x44, (byte)0x01, (byte)0xf5, (byte)0x1e, (byte)0x87,
            (byte)0x5e, (byte)0x61, (byte)0x2c, (byte)0x4b, (byte)0x1d, (byte)0x81, (byte)0x15, (byte)0xf4, (byte)0x23,
            (byte)0xd6, (byte)0xea, (byte)0xe1, (byte)0x67, (byte)0xf1, (byte)0x7f, (byte)0xfe, (byte)0xda, (byte)0x3c,
            (byte)0x07, (byte)0x53, (byte)0x6a, (byte)0x84, (byte)0x9c, (byte)0xcb, (byte)0x02, (byte)0x83, (byte)0x33,
            (byte)0xdd, (byte)0x35, (byte)0xe2, (byte)0x59, (byte)0x5a, (byte)0x98, (byte)0xa5, (byte)0x92, (byte)0x64,
            (byte)0x04, (byte)0x06, (byte)0x10, (byte)0x4d, (byte)0x1c, (byte)0x97, (byte)0x08, (byte)0x31, (byte)0xee,
            (byte)0xab, (byte)0x05, (byte)0xaf, (byte)0x79, (byte)0xa0, (byte)0x18, (byte)0x46, (byte)0x6d, (byte)0xfc,
            (byte)0x89, (byte)0xd4, (byte)0xc7, (byte)0xff, (byte)0xf0, (byte)0xcf, (byte)0x42, (byte)0x91, (byte)0xf8,
            (byte)0x68, (byte)0x0a, (byte)0x65, (byte)0x8e, (byte)0xb6, (byte)0xfd, (byte)0xc3, (byte)0xef, (byte)0x78,
            (byte)0x4c, (byte)0xcc, (byte)0x9e, (byte)0x30, (byte)0x2e, (byte)0xbc, (byte)0x0b, (byte)0x54, (byte)0x1a,
            (byte)0xa6, (byte)0xbb, (byte)0x26, (byte)0x80, (byte)0x48, (byte)0x94, (byte)0x32, (byte)0x7d, (byte)0xa7,
            (byte)0x3f, (byte)0xae, (byte)0x22, (byte)0x3d, (byte)0x66, (byte)0xaa, (byte)0xf6, (byte)0x00, (byte)0x5d,
            (byte)0xbd, (byte)0x4a, (byte)0xe0, (byte)0x3b, (byte)0xb4, (byte)0x17, (byte)0x8b, (byte)0x9f, (byte)0x76,
            (byte)0xb0, (byte)0x24, (byte)0x9a, (byte)0x25, (byte)0x63, (byte)0xdb, (byte)0xeb, (byte)0x7a, (byte)0x3e,
            (byte)0x5c, (byte)0xb3, (byte)0xb1, (byte)0x29, (byte)0xf2, (byte)0xca, (byte)0x58, (byte)0x6e, (byte)0xd8,
            (byte)0xa8, (byte)0x2f, (byte)0x75, (byte)0xdf, (byte)0x14, (byte)0xfb, (byte)0x13, (byte)0x49, (byte)0x88,
            (byte)0xb2, (byte)0xec, (byte)0xe4, (byte)0x34, (byte)0x2d, (byte)0x96, (byte)0xc6, (byte)0x3a, (byte)0xed,
            (byte)0x95, (byte)0x0e, (byte)0xe5, (byte)0x85, (byte)0x6b, (byte)0x40, (byte)0x21, (byte)0x9b, (byte)0x09,
            (byte)0x19, (byte)0x2b, (byte)0x52, (byte)0xde, (byte)0x45, (byte)0xa3, (byte)0xfa, (byte)0x51, (byte)0xc2,
            (byte)0xb5, (byte)0xd1, (byte)0x90, (byte)0xb9, (byte)0xf3, (byte)0x37, (byte)0xc1, (byte)0x0d, (byte)0xba,
            (byte)0x41, (byte)0x11, (byte)0x38, (byte)0x7b, (byte)0xbe, (byte)0xd0, (byte)0xd5, (byte)0x69, (byte)0x36,
            (byte)0xc8, (byte)0x62, (byte)0x1b, (byte)0x82, (byte)0x8f },

        new byte[]{ (byte)0x83, (byte)0xf2, (byte)0x2a, (byte)0xeb, (byte)0xe9, (byte)0xbf, (byte)0x7b, (byte)0x9c,
            (byte)0x34, (byte)0x96, (byte)0x8d, (byte)0x98, (byte)0xb9, (byte)0x69, (byte)0x8c, (byte)0x29, (byte)0x3d,
            (byte)0x88, (byte)0x68, (byte)0x06, (byte)0x39, (byte)0x11, (byte)0x4c, (byte)0x0e, (byte)0xa0, (byte)0x56,
            (byte)0x40, (byte)0x92, (byte)0x15, (byte)0xbc, (byte)0xb3, (byte)0xdc, (byte)0x6f, (byte)0xf8, (byte)0x26,
            (byte)0xba, (byte)0xbe, (byte)0xbd, (byte)0x31, (byte)0xfb, (byte)0xc3, (byte)0xfe, (byte)0x80, (byte)0x61,
            (byte)0xe1, (byte)0x7a, (byte)0x32, (byte)0xd2, (byte)0x70, (byte)0x20, (byte)0xa1, (byte)0x45, (byte)0xec,
            (byte)0xd9, (byte)0x1a, (byte)0x5d, (byte)0xb4, (byte)0xd8, (byte)0x09, (byte)0xa5, (byte)0x55, (byte)0x8e,
            (byte)0x37, (byte)0x76, (byte)0xa9, (byte)0x67, (byte)0x10, (byte)0x17, (byte)0x36, (byte)0x65, (byte)0xb1,
            (byte)0x95, (byte)0x62, (byte)0x59, (byte)0x74, (byte)0xa3, (byte)0x50, (byte)0x2f, (byte)0x4b, (byte)0xc8,
            (byte)0xd0, (byte)0x8f, (byte)0xcd, (byte)0xd4, (byte)0x3c, (byte)0x86, (byte)0x12, (byte)0x1d, (byte)0x23,
            (byte)0xef, (byte)0xf4, (byte)0x53, (byte)0x19, (byte)0x35, (byte)0xe6, (byte)0x7f, (byte)0x5e, (byte)0xd6,
            (byte)0x79, (byte)0x51, (byte)0x22, (byte)0x14, (byte)0xf7, (byte)0x1e, (byte)0x4a, (byte)0x42, (byte)0x9b,
            (byte)0x41, (byte)0x73, (byte)0x2d, (byte)0xc1, (byte)0x5c, (byte)0xa6, (byte)0xa2, (byte)0xe0, (byte)0x2e,
            (byte)0xd3, (byte)0x28, (byte)0xbb, (byte)0xc9, (byte)0xae, (byte)0x6a, (byte)0xd1, (byte)0x5a, (byte)0x30,
            (byte)0x90, (byte)0x84, (byte)0xf9, (byte)0xb2, (byte)0x58, (byte)0xcf, (byte)0x7e, (byte)0xc5, (byte)0xcb,
            (byte)0x97, (byte)0xe4, (byte)0x16, (byte)0x6c, (byte)0xfa, (byte)0xb0, (byte)0x6d, (byte)0x1f, (byte)0x52,
            (byte)0x99, (byte)0x0d, (byte)0x4e, (byte)0x03, (byte)0x91, (byte)0xc2, (byte)0x4d, (byte)0x64, (byte)0x77,
            (byte)0x9f, (byte)0xdd, (byte)0xc4, (byte)0x49, (byte)0x8a, (byte)0x9a, (byte)0x24, (byte)0x38, (byte)0xa7,
            (byte)0x57, (byte)0x85, (byte)0xc7, (byte)0x7c, (byte)0x7d, (byte)0xe7, (byte)0xf6, (byte)0xb7, (byte)0xac,
            (byte)0x27, (byte)0x46, (byte)0xde, (byte)0xdf, (byte)0x3b, (byte)0xd7, (byte)0x9e, (byte)0x2b, (byte)0x0b,
            (byte)0xd5, (byte)0x13, (byte)0x75, (byte)0xf0, (byte)0x72, (byte)0xb6, (byte)0x9d, (byte)0x1b, (byte)0x01,
            (byte)0x3f, (byte)0x44, (byte)0xe5, (byte)0x87, (byte)0xfd, (byte)0x07, (byte)0xf1, (byte)0xab, (byte)0x94,
            (byte)0x18, (byte)0xea, (byte)0xfc, (byte)0x3a, (byte)0x82, (byte)0x5f, (byte)0x05, (byte)0x54, (byte)0xdb,
            (byte)0x00, (byte)0x8b, (byte)0xe3, (byte)0x48, (byte)0x0c, (byte)0xca, (byte)0x78, (byte)0x89, (byte)0x0a,
            (byte)0xff, (byte)0x3e, (byte)0x5b, (byte)0x81, (byte)0xee, (byte)0x71, (byte)0xe2, (byte)0xda, (byte)0x2c,
            (byte)0xb8, (byte)0xb5, (byte)0xcc, (byte)0x6e, (byte)0xa8, (byte)0x6b, (byte)0xad, (byte)0x60, (byte)0xc6,
            (byte)0x08, (byte)0x04, (byte)0x02, (byte)0xe8, (byte)0xf5, (byte)0x4f, (byte)0xa4, (byte)0xf3, (byte)0xc0,
            (byte)0xce, (byte)0x43, (byte)0x25, (byte)0x1c, (byte)0x21, (byte)0x33, (byte)0x0f, (byte)0xaf, (byte)0x47,
            (byte)0xed, (byte)0x66, (byte)0x63, (byte)0x93, (byte)0xaa },

        new byte[]{ (byte)0x45, (byte)0xd4, (byte)0x0b, (byte)0x43, (byte)0xf1, (byte)0x72, (byte)0xed, (byte)0xa4,
            (byte)0xc2, (byte)0x38, (byte)0xe6, (byte)0x71, (byte)0xfd, (byte)0xb6, (byte)0x3a, (byte)0x95, (byte)0x50,
            (byte)0x44, (byte)0x4b, (byte)0xe2, (byte)0x74, (byte)0x6b, (byte)0x1e, (byte)0x11, (byte)0x5a, (byte)0xc6,
            (byte)0xb4, (byte)0xd8, (byte)0xa5, (byte)0x8a, (byte)0x70, (byte)0xa3, (byte)0xa8, (byte)0xfa, (byte)0x05,
            (byte)0xd9, (byte)0x97, (byte)0x40, (byte)0xc9, (byte)0x90, (byte)0x98, (byte)0x8f, (byte)0xdc, (byte)0x12,
            (byte)0x31, (byte)0x2c, (byte)0x47, (byte)0x6a, (byte)0x99, (byte)0xae, (byte)0xc8, (byte)0x7f, (byte)0xf9,
            (byte)0x4f, (byte)0x5d, (byte)0x96, (byte)0x6f, (byte)0xf4, (byte)0xb3, (byte)0x39, (byte)0x21, (byte)0xda,
            (byte)0x9c, (byte)0x85, (byte)0x9e, (byte)0x3b, (byte)0xf0, (byte)0xbf, (byte)0xef, (byte)0x06, (byte)0xee,
            (byte)0xe5, (byte)0x5f, (byte)0x20, (byte)0x10, (byte)0xcc, (byte)0x3c, (byte)0x54, (byte)0x4a, (byte)0x52,
            (byte)0x94, (byte)0x0e, (byte)0xc0, (byte)0x28, (byte)0xf6, (byte)0x56, (byte)0x60, (byte)0xa2, (byte)0xe3,
            (byte)0x0f, (byte)0xec, (byte)0x9d, (byte)0x24, (byte)0x83, (byte)0x7e, (byte)0xd5, (byte)0x7c, (byte)0xeb,
            (byte)0x18, (byte)0xd7, (byte)0xcd, (byte)0xdd, (byte)0x78, (byte)0xff, (byte)0xdb, (byte)0xa1, (byte)0x09,
            (byte)0xd0, (byte)0x76, (byte)0x84, (byte)0x75, (byte)0xbb, (byte)0x1d, (byte)0x1a, (byte)0x2f, (byte)0xb0,
            (byte)0xfe, (byte)0xd6, (byte)0x34, (byte)0x63, (byte)0x35, (byte)0xd2, (byte)0x2a, (byte)0x59, (byte)0x6d,
            (byte)0x4d, (byte)0x77, (byte)0xe7, (byte)0x8e, (byte)0x61, (byte)0xcf, (byte)0x9f, (byte)0xce, (byte)0x27,
            (byte)0xf5, (byte)0x80, (byte)0x86, (byte)0xc7, (byte)0xa6, (byte)0xfb, (byte)0xf8, (byte)0x87, (byte)0xab,
            (byte)0x62, (byte)0x3f, (byte)0xdf, (byte)0x48, (byte)0x00, (byte)0x14, (byte)0x9a, (byte)0xbd, (byte)0x5b,
            (byte)0x04, (byte)0x92, (byte)0x02, (byte)0x25, (byte)0x65, (byte)0x4c, (byte)0x53, (byte)0x0c, (byte)0xf2,
            (byte)0x29, (byte)0xaf, (byte)0x17, (byte)0x6c, (byte)0x41, (byte)0x30, (byte)0xe9, (byte)0x93, (byte)0x55,
            (byte)0xf7, (byte)0xac, (byte)0x68, (byte)0x26, (byte)0xc4, (byte)0x7d, (byte)0xca, (byte)0x7a, (byte)0x3e,
            (byte)0xa0, (byte)0x37, (byte)0x03, (byte)0xc1, (byte)0x36, (byte)0x69, (byte)0x66, (byte)0x08, (byte)0x16,
            (byte)0xa7, (byte)0xbc, (byte)0xc5, (byte)0xd3, (byte)0x22, (byte)0xb7, (byte)0x13, (byte)0x46, (byte)0x32,
            (byte)0xe8, (byte)0x57, (byte)0x88, (byte)0x2b, (byte)0x81, (byte)0xb2, (byte)0x4e, (byte)0x64, (byte)0x1c,
            (byte)0xaa, (byte)0x91, (byte)0x58, (byte)0x2e, (byte)0x9b, (byte)0x5c, (byte)0x1b, (byte)0x51, (byte)0x73,
            (byte)0x42, (byte)0x23, (byte)0x01, (byte)0x6e, (byte)0xf3, (byte)0x0d, (byte)0xbe, (byte)0x3d, (byte)0x0a,
            (byte)0x2d, (byte)0x1f, (byte)0x67, (byte)0x33, (byte)0x19, (byte)0x7b, (byte)0x5e, (byte)0xea, (byte)0xde,
            (byte)0x8b, (byte)0xcb, (byte)0xa9, (byte)0x8c, (byte)0x8d, (byte)0xad, (byte)0x49, (byte)0x82, (byte)0xe4,
            (byte)0xba, (byte)0xc3, (byte)0x15, (byte)0xd1, (byte)0xe0, (byte)0x89, (byte)0xfc, (byte)0xb1, (byte)0xb9,
            (byte)0xb5, (byte)0x07, (byte)0x79, (byte)0xb8, (byte)0xe1 },

        new byte[]{ (byte)0xb2, (byte)0xb6, (byte)0x23, (byte)0x11, (byte)0xa7, (byte)0x88, (byte)0xc5, (byte)0xa6,
            (byte)0x39, (byte)0x8f, (byte)0xc4, (byte)0xe8, (byte)0x73, (byte)0x22, (byte)0x43, (byte)0xc3, (byte)0x82,
            (byte)0x27, (byte)0xcd, (byte)0x18, (byte)0x51, (byte)0x62, (byte)0x2d, (byte)0xf7, (byte)0x5c, (byte)0x0e,
            (byte)0x3b, (byte)0xfd, (byte)0xca, (byte)0x9b, (byte)0x0d, (byte)0x0f, (byte)0x79, (byte)0x8c, (byte)0x10,
            (byte)0x4c, (byte)0x74, (byte)0x1c, (byte)0x0a, (byte)0x8e, (byte)0x7c, (byte)0x94, (byte)0x07, (byte)0xc7,
            (byte)0x5e, (byte)0x14, (byte)0xa1, (byte)0x21, (byte)0x57, (byte)0x50, (byte)0x4e, (byte)0xa9, (byte)0x80,
            (byte)0xd9, (byte)0xef, (byte)0x64, (byte)0x41, (byte)0xcf, (byte)0x3c, (byte)0xee, (byte)0x2e, (byte)0x13,
            (byte)0x29, (byte)0xba, (byte)0x34, (byte)0x5a, (byte)0xae, (byte)0x8a, (byte)0x61, (byte)0x33, (byte)0x12,
            (byte)0xb9, (byte)0x55, (byte)0xa8, (byte)0x15, (byte)0x05, (byte)0xf6, (byte)0x03, (byte)0x06, (byte)0x49,
            (byte)0xb5, (byte)0x25, (byte)0x09, (byte)0x16, (byte)0x0c, (byte)0x2a, (byte)0x38, (byte)0xfc, (byte)0x20,
            (byte)0xf4, (byte)0xe5, (byte)0x7f, (byte)0xd7, (byte)0x31, (byte)0x2b, (byte)0x66, (byte)0x6f, (byte)0xff,
            (byte)0x72, (byte)0x86, (byte)0xf0, (byte)0xa3, (byte)0x2f, (byte)0x78, (byte)0x00, (byte)0xbc, (byte)0xcc,
            (byte)0xe2, (byte)0xb0, (byte)0xf1, (byte)0x42, (byte)0xb4, (byte)0x30, (byte)0x5f, (byte)0x60, (byte)0x04,
            (byte)0xec, (byte)0xa5, (byte)0xe3, (byte)0x8b, (byte)0xe7, (byte)0x1d, (byte)0xbf, (byte)0x84, (byte)0x7b,
            (byte)0xe6, (byte)0x81, (byte)0xf8, (byte)0xde, (byte)0xd8, (byte)0xd2, (byte)0x17, (byte)0xce, (byte)0x4b,
            (byte)0x47, (byte)0xd6, (byte)0x69, (byte)0x6c, (byte)0x19, (byte)0x99, (byte)0x9a, (byte)0x01, (byte)0xb3,
            (byte)0x85, (byte)0xb1, (byte)0xf9, (byte)0x59, (byte)0xc2, (byte)0x37, (byte)0xe9, (byte)0xc8, (byte)0xa0,
            (byte)0xed, (byte)0x4f, (byte)0x89, (byte)0x68, (byte)0x6d, (byte)0xd5, (byte)0x26, (byte)0x91, (byte)0x87,
            (byte)0x58, (byte)0xbd, (byte)0xc9, (byte)0x98, (byte)0xdc, (byte)0x75, (byte)0xc0, (byte)0x76, (byte)0xf5,
            (byte)0x67, (byte)0x6b, (byte)0x7e, (byte)0xeb, (byte)0x52, (byte)0xcb, (byte)0xd1, (byte)0x5b, (byte)0x9f,
            (byte)0x0b, (byte)0xdb, (byte)0x40, (byte)0x92, (byte)0x1a, (byte)0xfa, (byte)0xac, (byte)0xe4, (byte)0xe1,
            (byte)0x71, (byte)0x1f, (byte)0x65, (byte)0x8d, (byte)0x97, (byte)0x9e, (byte)0x95, (byte)0x90, (byte)0x5d,
            (byte)0xb7, (byte)0xc1, (byte)0xaf, (byte)0x54, (byte)0xfb, (byte)0x02, (byte)0xe0, (byte)0x35, (byte)0xbb,
            (byte)0x3a, (byte)0x4d, (byte)0xad, (byte)0x2c, (byte)0x3d, (byte)0x56, (byte)0x08, (byte)0x1b, (byte)0x4a,
            (byte)0x93, (byte)0x6a, (byte)0xab, (byte)0xb8, (byte)0x7a, (byte)0xf2, (byte)0x7d, (byte)0xda, (byte)0x3f,
            (byte)0xfe, (byte)0x3e, (byte)0xbe, (byte)0xea, (byte)0xaa, (byte)0x44, (byte)0xc6, (byte)0xd0, (byte)0x36,
            (byte)0x48, (byte)0x70, (byte)0x96, (byte)0x77, (byte)0x24, (byte)0x53, (byte)0xdf, (byte)0xf3, (byte)0x83,
            (byte)0x28, (byte)0x32, (byte)0x45, (byte)0x1e, (byte)0xa4, (byte)0xd3, (byte)0xa2, (byte)0x46, (byte)0x6e,
            (byte)0x9c, (byte)0xdd, (byte)0x63, (byte)0xd4, (byte)0x9d } };
}
