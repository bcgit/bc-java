package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/**
 * LEA Cipher engine.
 */
public class LEAEngine
    implements BlockCipher
{
    /**
     * Base number of rounds.
     */
    private static final int BASEROUNDS = 16;

    /**
     * Number of words in state.
     */
    private static final int NUMWORDS = 4;

    /**
     * Number of words in 128-bit key.
     */
    private static final int NUMWORDS128 = 4;

    /**
     * Mask for mod 4.
     */
    private static final int MASK128 = NUMWORDS128 - 1;

    /**
     * Number of words in 192-bit key.
     */
    private static final int NUMWORDS192 = 6;

    /**
     * Number of words in 256-bit key.
     */
    private static final int NUMWORDS256 = 8;

    /**
     * Mask for mod 8.
     */
    private static final int MASK256 = NUMWORDS256 - 1;

    /**
     * BlockSize.
     */
    private static final int BLOCKSIZE = NUMWORDS * Integers.BYTES;

    /**
     * keyIndex0.
     */
    private static final int KEY0 = 0;

    /**
     * keyIndex1.
     */
    private static final int KEY1 = 1;

    /**
     * keyIndex2.
     */
    private static final int KEY2 = 2;

    /**
     * keyIndex3.
     */
    private static final int KEY3 = 3;

    /**
     * keyIndex4.
     */
    private static final int KEY4 = 4;

    /**
     * keyIndex5.
     */
    private static final int KEY5 = 5;

    /**
     * Rotate1.
     */
    private static final int ROT1 = 1;

    /**
     * Rotate3.
     */
    private static final int ROT3 = 3;

    /**
     * Rotate5.
     */
    private static final int ROT5 = 5;

    /**
     * Rotate6.
     */
    private static final int ROT6 = 6;

    /**
     * Rotate9.
     */
    private static final int ROT9 = 9;

    /**
     * Rotate11.
     */
    private static final int ROT11 = 11;

    /**
     * Rotate13.
     */
    private static final int ROT13 = 13;

    /**
     * Rotate17.
     */
    private static final int ROT17 = 17;

    /**
     * Delta values.
     */
    private static final int[] DELTA =
        {
            0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
        };

    /**
     * The work buffer.
     */
    private final int[] theBlock;

    /**
     * The # of rounds.
     */
    private int theRounds;

    /**
     * The round keys.
     */
    private int[][] theRoundKeys;

    /**
     * Are we encrypting?
     */
    private boolean forEncryption;

    /**
     * Constructor.
     */
    public LEAEngine()
    {
        theBlock = new int[NUMWORDS];
    }

    public void init(final boolean pEncrypt,
                     final CipherParameters pParams)
    {
        /* Reject invalid parameters */
        if (!(pParams instanceof KeyParameter))
        {
            throw new IllegalArgumentException("Invalid parameter passed to LEA init - "
                + pParams.getClass().getName());
        }

        /* Validate keyLength */
        final byte[] myKey = ((KeyParameter)pParams).getKey();
        final int myKeyLen = myKey.length;
        if ((((myKeyLen << 1) % BLOCKSIZE) != 0)
            || myKeyLen < BLOCKSIZE
            || myKeyLen > (BLOCKSIZE << 1))
        {
            throw new IllegalArgumentException("KeyBitSize must be 128, 192 or 256");
        }

        /* Generate the round keys */
        forEncryption = pEncrypt;

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(getAlgorithmName(), myKeyLen * 8, pParams, Utils.getPurpose(forEncryption)));

        generateRoundKeys(myKey);
    }

    public void reset()
    {
        /* NoOp */
    }

    public String getAlgorithmName()
    {
        return "LEA";
    }

    public int getBlockSize()
    {
        return BLOCKSIZE;
    }

    public int processBlock(final byte[] pInput,
                            final int pInOff,
                            final byte[] pOutput,
                            final int pOutOff)
    {
        /* Check buffers */
        checkBuffer(pInput, pInOff, false);
        checkBuffer(pOutput, pOutOff, true);

        /* Perform the encryption/decryption */
        return forEncryption
            ? encryptBlock(pInput, pInOff, pOutput, pOutOff)
            : decryptBlock(pInput, pInOff, pOutput, pOutOff);
    }

    /**
     * Obtain buffer length (allowing for null).
     *
     * @param pBuffer the buffer
     * @return the length
     */
    private static int bufLength(final byte[] pBuffer)
    {
        return pBuffer == null ? 0 : pBuffer.length;
    }

    /**
     * Check buffer.
     *
     * @param pBuffer the buffer
     * @param pOffset the offset
     * @param pOutput is this an output buffer?
     */
    private static void checkBuffer(final byte[] pBuffer,
                                    final int pOffset,
                                    final boolean pOutput)
    {
        /* Access lengths */
        final int myBufLen = bufLength(pBuffer);
        final int myLast = pOffset + BLOCKSIZE;

        /* Check for negative values and buffer overflow */
        final boolean badLen = pOffset < 0 || myLast < 0;
        if (badLen || myLast > myBufLen)
        {
            throw pOutput
                ? new OutputLengthException("Output buffer too short.")
                : new DataLengthException("Input buffer too short.");
        }
    }

    /**
     * Encrypt a block.
     *
     * @param pInput  the input buffer
     * @param pInOff  the input offset
     * @param pOutput the output offset
     * @param pOutOff the output offset
     * @return the bytes processed
     */
    private int encryptBlock(final byte[] pInput,
                             final int pInOff,
                             final byte[] pOutput,
                             final int pOutOff)
    {
        /* Load the bytes into the block */
        Pack.littleEndianToInt(pInput, pInOff, theBlock, 0, NUMWORDS);

        /* Loop through the rounds */
        for (int i = 0; i < theRounds; i++)
        {
            encryptRound(i);
        }

        /* Output the bytes from the block */
        Pack.intToLittleEndian(theBlock, pOutput, pOutOff);

        /* Return # of bytes processed */
        return BLOCKSIZE;
    }

    /**
     * Encrypt a round.
     *
     * @param pRound the round#
     */
    private void encryptRound(final int pRound)
    {
        final int[] myKeys = theRoundKeys[pRound];
        int myIndex = (NUMWORDS - 1 + pRound) % NUMWORDS;
        int myNextIndex = leftIndex(myIndex);
        theBlock[myIndex] = ror32((theBlock[myNextIndex] ^ myKeys[KEY4]) + (theBlock[myIndex] ^ myKeys[KEY5]), ROT3);
        myIndex = myNextIndex;
        myNextIndex = leftIndex(myIndex);
        theBlock[myIndex] = ror32((theBlock[myNextIndex] ^ myKeys[KEY2]) + (theBlock[myIndex] ^ myKeys[KEY3]), ROT5);
        myIndex = myNextIndex;
        myNextIndex = leftIndex(myIndex);
        theBlock[myIndex] = rol32((theBlock[myNextIndex] ^ myKeys[KEY0]) + (theBlock[myIndex] ^ myKeys[KEY1]), ROT9);
    }

    /**
     * Return the left of an index.
     *
     * @param pIndex the index
     * @return the left of an index
     */
    private static int leftIndex(final int pIndex)
    {
        return pIndex == 0 ? NUMWORDS - 1 : pIndex - 1;
    }

    /**
     * Decrypt a block.
     *
     * @param pInput  the input buffer
     * @param pInOff  the input offset
     * @param pOutput the output offset
     * @param pOutOff the output offset
     * @return the bytes processed
     */
    private int decryptBlock(final byte[] pInput,
                             final int pInOff,
                             final byte[] pOutput,
                             final int pOutOff)
    {
        /* Load the bytes into the block */
        Pack.littleEndianToInt(pInput, pInOff, theBlock, 0, NUMWORDS);

        /* Loop through the rounds */
        for (int i = theRounds - 1; i >= 0; i--)
        {
            decryptRound(i);
        }

        /* Output the bytes from the block */
        Pack.intToLittleEndian(theBlock, pOutput, pOutOff);

        /* Return # of bytes processed */
        return BLOCKSIZE;
    }

    /**
     * Decrypt a round.
     *
     * @param pRound the round#
     */
    private void decryptRound(final int pRound)
    {
        final int[] myKeys = theRoundKeys[pRound];
        int myPrevIndex = pRound % NUMWORDS;
        int myIndex = rightIndex(myPrevIndex);
        theBlock[myIndex] = (ror32(theBlock[myIndex], ROT9) - (theBlock[myPrevIndex] ^ myKeys[KEY0])) ^ myKeys[KEY1];
        myPrevIndex = myIndex;
        myIndex = rightIndex(myIndex);
        theBlock[myIndex] = (rol32(theBlock[myIndex], ROT5) - (theBlock[myPrevIndex] ^ myKeys[KEY2])) ^ myKeys[KEY3];
        myPrevIndex = myIndex;
        myIndex = rightIndex(myIndex);
        theBlock[myIndex] = (rol32(theBlock[myIndex], ROT3) - (theBlock[myPrevIndex] ^ myKeys[KEY4])) ^ myKeys[KEY5];
    }

    /**
     * Return the left of an index.
     *
     * @param pIndex the index
     * @return the left of an index
     */
    private static int rightIndex(final int pIndex)
    {
        return pIndex == NUMWORDS - 1 ? 0 : pIndex + 1;
    }

    /**
     * Generate the round keys.
     *
     * @param pKey the key
     */
    private void generateRoundKeys(final byte[] pKey)
    {
        /* Determine the rounds and allocate round keys */
        theRounds = (pKey.length >> 1) + BASEROUNDS;
        theRoundKeys = new int[theRounds][NUMWORDS192];
        final int numWords = pKey.length / Integers.BYTES;

        /* Create and initialise working array */
        final int[] myT = new int[numWords];
        Pack.littleEndianToInt(pKey, 0, myT, 0, numWords);

        /* Switch on number of words in the key */
        switch (numWords)
        {
        case NUMWORDS128:
            generate128RoundKeys(myT);
            break;
        case NUMWORDS192:
            generate192RoundKeys(myT);
            break;
        case NUMWORDS256:
        default:
            generate256RoundKeys(myT);
            break;
        }
    }

    /**
     * Generate the round keys from 128-bit key.
     *
     * @param pWork the working keys
     */
    private void generate128RoundKeys(final int[] pWork)
    {
        for (int i = 0; i < theRounds; ++i)
        {
            final int myDelta = rol32(DELTA[i & MASK128], i);

            int j = 0;
            pWork[j] = rol32(pWork[j++] + myDelta, ROT1);
            pWork[j] = rol32(pWork[j] + rol32(myDelta, j++), ROT3);
            pWork[j] = rol32(pWork[j] + rol32(myDelta, j++), ROT6);
            pWork[j] = rol32(pWork[j] + rol32(myDelta, j), ROT11);

            final int[] myKeys = theRoundKeys[i];
            myKeys[KEY0] = pWork[KEY0];
            myKeys[KEY1] = pWork[KEY1];
            myKeys[KEY2] = pWork[KEY2];
            myKeys[KEY3] = pWork[KEY1];
            myKeys[KEY4] = pWork[KEY3];
            myKeys[KEY5] = pWork[KEY1];
        }
    }

    /**
     * Generate the round keys from 192-bit key.
     *
     * @param pWork the working keys
     */
    private void generate192RoundKeys(final int[] pWork)
    {
        for (int i = 0; i < theRounds; ++i)
        {
            final int myDelta = rol32(DELTA[i % NUMWORDS192], i);

            int j = 0;
            pWork[j] = rol32(pWork[j] + rol32(myDelta, j++), ROT1);
            pWork[j] = rol32(pWork[j] + rol32(myDelta, j++), ROT3);
            pWork[j] = rol32(pWork[j] + rol32(myDelta, j++), ROT6);
            pWork[j] = rol32(pWork[j] + rol32(myDelta, j++), ROT11);
            pWork[j] = rol32(pWork[j] + rol32(myDelta, j++), ROT13);
            pWork[j] = rol32(pWork[j] + rol32(myDelta, j++), ROT17);
            System.arraycopy(pWork, 0, theRoundKeys[i], 0, j);
        }
    }

    /**
     * Generate the round keys from 256-bit key.
     *
     * @param pWork the working keys
     */
    private void generate256RoundKeys(final int[] pWork)
    {
        int index = 0;
        for (int i = 0; i < theRounds; ++i)
        {
            final int myDelta = rol32(DELTA[i & MASK256], i);
            final int[] myKeys = theRoundKeys[i];

            int j = 0;
            myKeys[j] = rol32(pWork[index & MASK256] + myDelta, ROT1);
            pWork[index++ & MASK256] = myKeys[j++];
            myKeys[j] = rol32(pWork[index & MASK256] + rol32(myDelta, j), ROT3);
            pWork[index++ & MASK256] = myKeys[j++];
            myKeys[j] = rol32(pWork[index & MASK256] + rol32(myDelta, j), ROT6);
            pWork[index++ & MASK256] = myKeys[j++];
            myKeys[j] = rol32(pWork[index & MASK256] + rol32(myDelta, j), ROT11);
            pWork[index++ & MASK256] = myKeys[j++];
            myKeys[j] = rol32(pWork[index & MASK256] + rol32(myDelta, j), ROT13);
            pWork[index++ & MASK256] = myKeys[j++];
            myKeys[j] = rol32(pWork[index & MASK256] + rol32(myDelta, j), ROT17);
            pWork[index++ & MASK256] = myKeys[j];
        }
    }

    /**
     * rotate left.
     *
     * @param pValue the value to rotate
     * @param pBits  the # of bits to rotate
     * @return the rotated value
     */
    private static int rol32(final int pValue,
                             final int pBits)
    {
        return (pValue << pBits) | (pValue >>> (Integers.SIZE - pBits));
    }

    /**
     * rotate right.
     *
     * @param pValue the value to rotate
     * @param pBits  the # of bits to rotate
     * @return the rotated value
     */
    private static int ror32(final int pValue,
                             final int pBits)
    {
        return (pValue >>> pBits) | (pValue << (Integers.SIZE - pBits));
    }
}
