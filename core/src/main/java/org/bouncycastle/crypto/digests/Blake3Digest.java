package org.bouncycastle.crypto.digests;

import java.util.Iterator;
import java.util.Stack;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.params.Blake3Parameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * Blake3 implementation.
 */
public class Blake3Digest
        implements ExtendedDigest, Memoable, Xof
{
    /**
     * Already outputting error.
     */
    private static final String ERR_OUTPUTTING = "Already outputting";

    /**
     * Number of Words.
     */
    private static final int NUMWORDS = 8;

    /**
     * Number of Rounds.
     */
    private static final int ROUNDS = 7;

    /**
     * Buffer length.
     */
    private static final int BLOCKLEN = NUMWORDS * Integers.BYTES * 2;

    /**
     * Chunk length.
     */
    private static final int CHUNKLEN = 1024;

    /**
     * ChunkStart Flag.
     */
    private static final int CHUNKSTART    = 1;

    /**
     * ChunkEnd Flag.
     */
    private static final int CHUNKEND      = 2;

    /**
     * Parent Flag.
     */
    private static final int PARENT        = 4;

    /**
     * Root Flag.
     */
    private static final int ROOT          = 8;

    /**
     * KeyedHash Flag.
     */
    private static final int KEYEDHASH     = 16;

    /**
     * DeriveContext Flag.
     */
    private static final int DERIVECONTEXT = 32;

    /**
     * DeriveKey Flag.
     */
    private static final int DERIVEKEY     = 64;

    /**
     * Chaining0 State Locations.
     */
    private static final int CHAINING0 = 0;

    /**
     * Chaining1 State Location.
     */
    private static final int CHAINING1 = 1;

    /**
     * Chaining2 State Location.
     */
    private static final int CHAINING2 = 2;

    /**
     * Chaining3 State Location.
     */
    private static final int CHAINING3 = 3;

    /**
     * Chaining4 State Location.
     */
    private static final int CHAINING4 = 4;

    /**
     * Chaining5 State Location.
     */
    private static final int CHAINING5 = 5;

    /**
     * Chaining6 State Location.
     */
    private static final int CHAINING6 = 6;

    /**
     * Chaining7 State Location.
     */
    private static final int CHAINING7 = 7;

    /**
     * IV0 State Locations.
     */
    private static final int IV0       = 8;

    /**
     * IV1 State Location.
     */
    private static final int IV1       = 9;

    /**
     * IV2 State Location.
     */
    private static final int IV2       = 10;

    /**
     * IV3 State Location.
     */
    private static final int IV3       = 11;

    /**
     * Count0 State Location.
     */
    private static final int COUNT0    = 12;

    /**
     * Count1 State Location.
     */
    private static final int COUNT1    = 13;

    /**
     * DataLen State Location.
     */
    private static final int DATALEN   = 14;

    /**
     * Flags State Location.
     */
    private static final int FLAGS     = 15;

    /**
     * Message word permutations.
     */
    private static final byte[] SIGMA = { 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };

    /**
     * Rotation constants.
     */
    private static final byte[] ROTATE = { 16, 12, 8, 7 };

    /**
     * Blake3 Initialization Vector.
     */
    private static final int[] IV = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    /**
     * The byte input/output buffer.
     */
    private final byte[] theBuffer = new byte[BLOCKLEN];

    /**
     * The key.
     */
    private final int[] theK = new int[NUMWORDS];

    /**
     * The chaining value.
     */
    private final int[] theChaining = new int[NUMWORDS];

    /**
     * The state.
     */
    private final int[] theV = new int[NUMWORDS << 1];

    /**
     * The message Buffer.
     */
    private final int[] theM = new int[NUMWORDS << 1];

    /**
     * The indices.
     */
    private final byte[] theIndices = new byte[NUMWORDS << 1];

    /**
     * The chainingStack.
     */
    private final Stack theStack = new Stack();

    /**
     * The default digestLength.
     */
    private final int theDigestLen;

    /**
     * Are we outputting?
     */
    private boolean outputting;

    /**
     * The current mode.
     */
    private int theMode;

    /**
     * The output mode.
     */
    private int theOutputMode;

    /**
     * The output dataLen.
     */
    private int theOutputDataLen;

    /**
     * The block counter.
     */
    private long theCounter;

    /**
     * The # of bytes in the current block.
     */
    private int theCurrBytes;

    /**
     * The position of the next byte in the buffer.
     */
    private int thePos;

    /**
     * Constructor.
     */
    public Blake3Digest()
    {
        this(BLOCKLEN >> 1);
    }

    /**
     * Constructor.
     * @param pDigestLen the default digestLength
     */
    public Blake3Digest(final int pDigestLen)
    {
        theDigestLen = pDigestLen;
        init(null);
    }

    /**
     * Constructor.
     * @param pSource the source digest.
     */
    private Blake3Digest(final Blake3Digest pSource)
    {
        /* Copy default digest length */
        theDigestLen = pSource.theDigestLen;

        /* Initialise from source */
        reset((Memoable) pSource);
    }

    public int getByteLength()
    {
        return BLOCKLEN;
    }

    public String getAlgorithmName()
    {
        return "BLAKE3";
    }

    public int getDigestSize()
    {
        return theDigestLen;
    }

    /**
     * Initialise.
     * @param pParams the parameters.
     */
    public void init(final Blake3Parameters pParams)
    {
        /* Access key/context */
        final byte[] myKey = pParams == null ? null : pParams.getKey();
        final byte[] myContext = pParams == null ? null : pParams.getContext();

        /* Reset the digest */
        reset();

        /* If we have a key  */
        if (myKey != null)
        {
            /* Initialise with the key */
            initKey(myKey);
            Arrays.fill(myKey, (byte) 0);

            /* else if we have a context */
        }
        else if (myContext != null)
        {
            /* Initialise for deriving context */
            initNullKey();
            theMode = DERIVECONTEXT;

            /* Derive key from context */
            update(myContext, 0, myContext.length);
            doFinal(theBuffer, 0);
            initKeyFromContext();
            reset();

            /* Else init null key and reset mode */
        }
        else
        {
            initNullKey();
            theMode = 0;
        }
    }

    public void update(final byte b)
    {
        /* Check that we are not outputting */
        if (outputting)
        {
            throw new IllegalStateException(ERR_OUTPUTTING);
        }

        /* If the buffer is full */
        final int blockLen = theBuffer.length;
        final int remainingLength = blockLen - thePos;
        if (remainingLength == 0)
        {
            /* Process the buffer */
            compressBlock(theBuffer, 0);

            /* Reset the buffer */
            Arrays.fill(theBuffer, (byte) 0);
            thePos = 0;
        }

        /* Store the byte */
        theBuffer[thePos] = b;
        thePos++;
    }

    public void update(final byte[] pMessage,
                       final int pOffset,
                       final int pLen)
    {
        /* Ignore null operation */
        if (pMessage == null || pLen == 0)
        {
            return;
        }

        /* Check that we are not outputting */
        if (outputting)
        {
            throw new IllegalStateException(ERR_OUTPUTTING);
        }

        /* Process any bytes currently in the buffer */
        int remainingLen = 0; // left bytes of buffer
        if (thePos != 0)
        {
            /* Calculate space remaining in the buffer */
            remainingLen = BLOCKLEN - thePos;

            /* If there is sufficient space in the buffer */
            if (remainingLen >= pLen)
            {
                /* Copy data into byffer and return */
                System.arraycopy(pMessage, pOffset, theBuffer, thePos, pLen);
                thePos += pLen;
                return;
            }

            /* Fill the buffer */
            System.arraycopy(pMessage, pOffset, theBuffer, thePos, remainingLen);

            /* Process the buffer */
            compressBlock(theBuffer, 0);

            /* Reset the buffer */
            thePos = 0;
            Arrays.fill(theBuffer, (byte) 0);
        }

        /* process all blocks except the last one */
        int messagePos;
        final int blockWiseLastPos = pOffset + pLen - BLOCKLEN;
        for (messagePos = pOffset + remainingLen; messagePos < blockWiseLastPos; messagePos += BLOCKLEN)
        {
            /* Process the buffer */
            compressBlock(pMessage, messagePos);
        }

        /* Fill the buffer with the remaining bytes of the message */
        final int len = pLen - messagePos;
        System.arraycopy(pMessage, messagePos, theBuffer, 0, pOffset + len);
        thePos += pOffset + len;
    }

    public int doFinal(final byte[] pOutput,
                       final int pOutOffset)
    {
        return doFinal(pOutput, pOutOffset, getDigestSize());
    }

    public int doFinal(final byte[] pOut,
                       final int pOutOffset,
                       final int pOutLen)
    {
        /* Reject if we are already outputting */
        if (outputting)
        {
            throw new IllegalStateException(ERR_OUTPUTTING);
        }

        /* Build the required output */
        final int length = doOutput(pOut, pOutOffset, pOutLen);

        /* reset the underlying digest and return the length */
        reset();
        return length;
    }

    public int doOutput(final byte[] pOut,
                        final int pOutOffset,
                        final int pOutLen)
    {
        /* If we have not started outputting yet */
        if (!outputting)
        {
            /* Process the buffer */
            compressFinalBlock(thePos);
        }

        /* If we have some remaining data in the current buffer */
        int dataLeft = pOutLen;
        int outPos = pOutOffset;
        if (thePos < BLOCKLEN)
        {
            /* Copy data from current hash */
            final int dataToCopy = Math.min(dataLeft, BLOCKLEN - thePos);
            System.arraycopy(theBuffer, thePos, pOut, outPos, dataToCopy);

            /* Adjust counters */
            thePos += dataToCopy;
            outPos += dataToCopy;
            dataLeft -= dataToCopy;
        }

        /* Loop until we have completed the request */
        while (dataLeft > 0)
        {
            /* Calculate the next block */
            nextOutputBlock();

            /* Copy data from current hash */
            final int dataToCopy = Math.min(dataLeft, BLOCKLEN);
            System.arraycopy(theBuffer, 0, pOut, outPos, dataToCopy);

            /* Adjust counters */
            thePos += dataToCopy;
            outPos += dataToCopy;
            dataLeft -= dataToCopy;
        }

        /* Return the number of bytes transferred */
        return pOutLen;
    }

    public void reset()
    {
        resetBlockCount();
        thePos = 0;
        outputting = false;
        Arrays.fill(theBuffer, (byte) 0);
    }

    public void reset(final Memoable pSource)
    {
        /* Access source */
        final Blake3Digest mySource = (Blake3Digest) pSource;

        /*  Reset counter */
        theCounter = mySource.theCounter;
        theCurrBytes = mySource.theCurrBytes;
        theMode = mySource.theMode;

        /* Reset output state */
        outputting = mySource.outputting;
        theOutputMode = mySource.theOutputMode;
        theOutputDataLen = mySource.theOutputDataLen;

        /* Copy state */
        System.arraycopy(mySource.theChaining, 0, theChaining, 0, theChaining.length);
        System.arraycopy(mySource.theK, 0, theK, 0, theK.length);
        System.arraycopy(mySource.theM, 0, theM, 0, theM.length);

        /* Copy stack */
        theStack.clear();
        for (Iterator it = mySource.theStack.iterator(); it.hasNext();)
        {
            theStack.push(Arrays.clone((int[])it.next()));
        }

        /* Copy buffer */
        System.arraycopy(mySource.theBuffer, 0, theBuffer, 0, theBuffer.length);
        thePos = mySource.thePos;
    }

    public Memoable copy()
    {
        return new Blake3Digest(this);
    }

    /**
     * Compress next block of the message.
     * @param pMessage the message buffer
     * @param pMsgPos the position within the message buffer
     */
    private void compressBlock(final byte[] pMessage,
                               final int pMsgPos)
    {
        /* Initialise state and compress message */
        initChunkBlock(BLOCKLEN, false);
        initM(pMessage, pMsgPos);
        compress();

        /* Adjust stack if we have completed a block */
        if (theCurrBytes == 0)
        {
            adjustStack();
        }
    }

    /**
     * Adjust the stack.
     */
    private void adjustStack()
    {
        /* Loop to combine blocks */
        long myCount = theCounter;
        while (myCount > 0)
        {
            /* Break loop if we are not combining */
            if ((myCount & 1) == 1)
            {
                break;
            }

            /* Build the message to be hashed */
            final int[] myLeft = (int[])theStack.pop();
            System.arraycopy(myLeft, 0, theM, 0, NUMWORDS);
            System.arraycopy(theChaining, 0, theM, NUMWORDS, NUMWORDS);

            /* Create parent block */
            initParentBlock();
            compress();

            /* Next block */
            myCount >>= 1;
        }

        /* Add back to the stack */
        theStack.push(Arrays.copyOf(theChaining, NUMWORDS));
    }

    /**
     * Compress final block.
     * @param pDataLen the data length
     */
    private void compressFinalBlock(final int pDataLen)
    {
        /* Initialise state and compress message */
        initChunkBlock(pDataLen, true);
        initM(theBuffer, 0);
        compress();

        /* Finalise stack */
        processStack();
    }

    /**
     * Process the stack.
     */
    private void processStack()
    {
        /* Finalise stack */
        while (!theStack.isEmpty())
        {
            /* Build the message to be hashed */
            final int[] myLeft = (int[])theStack.pop();
            System.arraycopy(myLeft, 0, theM, 0, NUMWORDS);
            System.arraycopy(theChaining, 0, theM, NUMWORDS, NUMWORDS);

            /* Create parent block */
            initParentBlock();
            if (theStack.isEmpty())
            {
                setRoot();
            }
            compress();
         }
    }

    /**
     * Perform compression.
      */
    private void compress()
    {
        /* Initialise the buffers */
        initIndices();

        /* Loop through the rounds */
        for (int round = 0; round < ROUNDS - 1; round++)
        {
            /* Perform the round and permuteM */
            performRound();
            permuteIndices();
        }
        performRound();
        adjustChaining();
    }

    /**
     * Perform a round.
     */
    private void performRound()
    {
        /* Apply to columns of V */
        int idx = 0;
        mixG(idx++, CHAINING0, CHAINING4, IV0, COUNT0);
        mixG(idx++, CHAINING1, CHAINING5, IV1, COUNT1);
        mixG(idx++, CHAINING2, CHAINING6, IV2, DATALEN);
        mixG(idx++, CHAINING3, CHAINING7, IV3, FLAGS);

        /* Apply to diagonals of V */
        mixG(idx++, CHAINING0, CHAINING5, IV2, FLAGS);
        mixG(idx++, CHAINING1, CHAINING6, IV3, COUNT0);
        mixG(idx++, CHAINING2, CHAINING7, IV0, COUNT1);
        mixG(idx, CHAINING3, CHAINING4, IV1, DATALEN);
    }

    /**
     * Initialise M from message.
     * @param pMessage the source message
     * @param pMsgPos the message position
     */
    private void initM(final byte[] pMessage,
                       final int pMsgPos)
    {
        /* Copy message bytes into word array */
        for (int i = 0; i < NUMWORDS << 1; i++)
        {
            theM[i] = Pack.littleEndianToInt(pMessage, pMsgPos + i * Integers.BYTES);
        }
    }

    /**
     * Adjust Chaining after compression.
     */
    private void adjustChaining()
    {
        /* If we are outputting */
        if (outputting)
        {
            /* Adjust full state */
            for (int i = 0; i < NUMWORDS; i++)
            {
                theV[i] ^= theV[i + NUMWORDS];
                theV[i + NUMWORDS] ^= theChaining[i];
            }

            /* Output state to buffer */
            for (int i = 0; i < NUMWORDS << 1; i++)
            {
                Pack.intToLittleEndian(theV[i], theBuffer, i * Integers.BYTES);
            }
            thePos = 0;

            /* Else just build chain value */
        }
        else
        {
            /* Combine V into Chaining */
            for (int i = 0; i < NUMWORDS; i++)
            {
                theChaining[i] = theV[i] ^ theV[i + NUMWORDS];
            }
        }
    }

    /**
     * Mix function G.
     * @param msgIdx the message index
     * @param posA position A in V
     * @param posB position B in V
     * @param posC position C in V
     * @param posD poistion D in V
     */
    private void mixG(final int msgIdx,
                      final int posA,
                      final int posB,
                      final int posC,
                      final int posD)
    {
        /* Determine indices */
        int msg = msgIdx << 1;
        int rot = 0;

        /* Perform the Round */
        theV[posA] += theV[posB] + theM[theIndices[msg++]];
        theV[posD] = Integers.rotateRight(theV[posD] ^ theV[posA], ROTATE[rot++]);
        theV[posC] += theV[posD];
        theV[posB] = Integers.rotateRight(theV[posB] ^ theV[posC], ROTATE[rot++]);
        theV[posA] += theV[posB] + theM[theIndices[msg]];
        theV[posD] = Integers.rotateRight(theV[posD] ^ theV[posA], ROTATE[rot++]);
        theV[posC] += theV[posD];
        theV[posB] = Integers.rotateRight(theV[posB] ^ theV[posC], ROTATE[rot]);
    }

    /**
     * initialise the indices.
     */
    private void initIndices()
    {
        for (byte i = 0; i < theIndices.length; i++)
        {
            theIndices[i] = i;
        }
    }

    /**
     * PermuteIndices.
     */
    private void permuteIndices()
    {
        for (byte i = 0; i < theIndices.length; i++)
        {
            theIndices[i] = SIGMA[theIndices[i]];
        }
    }

    /**
     * Initialise null key.
     */
    private void initNullKey()
    {
        System.arraycopy(IV, 0, theK, 0, NUMWORDS);
    }

    /**
     * Initialise key.
     * @param pKey the keyBytes
     */
    private void initKey(final byte[] pKey)
    {
        /* Copy message bytes into word array */
        for (int i = 0; i < NUMWORDS; i++)
        {
            theK[i] = Pack.littleEndianToInt(pKey, i * Integers.BYTES);
        }
        theMode = KEYEDHASH;
    }

    /**
     * Initialise key from context.
     */
    private void initKeyFromContext()
    {
        System.arraycopy(theV, 0, theK, 0, NUMWORDS);
        theMode = DERIVEKEY;
    }

    /**
     * Initialise chunk block.
     * @param pDataLen the dataLength
     * @param pFinal is this the final chunk?
     */
    private void initChunkBlock(final int pDataLen,
                                final boolean pFinal)
    {
        /* Initialise the block */
        System.arraycopy(theCurrBytes == 0 ? theK : theChaining, 0, theV, 0, NUMWORDS);
        System.arraycopy(IV, 0, theV, NUMWORDS, NUMWORDS >> 1);
        theV[COUNT0] = (int) theCounter;
        theV[COUNT1] = (int) (theCounter >> Integers.SIZE);
        theV[DATALEN] = pDataLen;
        theV[FLAGS] = theMode
                    + (theCurrBytes == 0 ? CHUNKSTART : 0)
                    + (pFinal ? CHUNKEND : 0);

        /* * Adjust block count */
        theCurrBytes += pDataLen;
        if (theCurrBytes >= CHUNKLEN)
        {
            incrementBlockCount();
            theV[FLAGS] |= CHUNKEND;
        }

        /* If we are single chunk */
        if (pFinal && theStack.isEmpty())
        {
            setRoot();
        }
    }

    /**
     * Initialise parent block.
     */
    private void initParentBlock()
    {
        /* Initialise the block */
        System.arraycopy(theK, 0, theV, 0, NUMWORDS);
        System.arraycopy(IV, 0, theV, NUMWORDS, NUMWORDS >> 1);
        theV[COUNT0] = 0;
        theV[COUNT1] = 0;
        theV[DATALEN] = BLOCKLEN;
        theV[FLAGS] = theMode | PARENT;
    }

    /**
     * Initialise output block.
     */
    private void nextOutputBlock()
    {
        /* Increment the counter */
        theCounter++;

        /* Initialise the block */
        System.arraycopy(theChaining, 0, theV, 0, NUMWORDS);
        System.arraycopy(IV, 0, theV, NUMWORDS, NUMWORDS >> 1);
        theV[COUNT0] = (int) theCounter;
        theV[COUNT1] = (int) (theCounter >> Integers.SIZE);
        theV[DATALEN] = theOutputDataLen;
        theV[FLAGS] = theOutputMode;

        /* Generate output */
        compress();
    }

    /**
     * IncrementBlockCount.
     */
    private void incrementBlockCount()
    {
        theCounter++;
        theCurrBytes = 0;
    }

    /**
     * ResetBlockCount.
     */
    private void resetBlockCount()
    {
        theCounter = 0;
        theCurrBytes = 0;
    }

    /**
     * Set root indication.
     */
    private void setRoot()
    {
        theV[FLAGS] |= ROOT;
        theOutputMode = theV[FLAGS];
        theOutputDataLen = theV[DATALEN];
        theCounter = 0;
        outputting = true;
        System.arraycopy(theV, 0, theChaining, 0, NUMWORDS);
    }
}
