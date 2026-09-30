package org.bouncycastle.crypto.digests;

import java.util.Iterator;
import java.util.Stack;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.OutputLengthException;
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
    private static final int CHUNKSTART = 1;

    /**
     * ChunkEnd Flag.
     */
    private static final int CHUNKEND = 2;

    /**
     * Parent Flag.
     */
    private static final int PARENT = 4;

    /**
     * Root Flag.
     */
    private static final int ROOT = 8;

    /**
     * KeyedHash Flag.
     */
    private static final int KEYEDHASH = 16;

    /**
     * DeriveContext Flag.
     */
    private static final int DERIVECONTEXT = 32;

    /**
     * DeriveKey Flag.
     */
    private static final int DERIVEKEY = 64;

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
    private static final int IV0 = 8;

    /**
     * IV1 State Location.
     */
    private static final int IV1 = 9;

    /**
     * IV2 State Location.
     */
    private static final int IV2 = 10;

    /**
     * IV3 State Location.
     */
    private static final int IV3 = 11;

    /**
     * Count0 State Location.
     */
    private static final int COUNT0 = 12;

    /**
     * Count1 State Location.
     */
    private static final int COUNT1 = 13;

    /**
     * DataLen State Location.
     */
    private static final int DATALEN = 14;

    /**
     * Flags State Location.
     */
    private static final int FLAGS = 15;

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
     * How many more bytes can we output?
     */
    private long outputAvailable;

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

    // digest purpose
    private final CryptoServicePurpose purpose;

    /**
     * Constructor.
     */
    public Blake3Digest()
    {
        this((BLOCKLEN >> 1) * 8);
    }

    /**
     * Constructor.
     *
     * @param pDigestSize the default digest size (in bits)
     */
    public Blake3Digest(final int pDigestSize)
    {
        // In aid of less confusion -this is to deal with the fact the
        // original checkin for this has the digest length in bytes
        // and every other digest we have doesn't....
        this(pDigestSize > 100 ? pDigestSize : pDigestSize * 8, CryptoServicePurpose.ANY);
    }

    /**
     * Base constructor with purpose.
     *
     * @param pDigestSize size of digest (in bits)
     * @param purpose usage purpose.
     */
    public Blake3Digest(final int pDigestSize, CryptoServicePurpose purpose)
    {
        this.purpose = purpose;
        theDigestLen = pDigestSize / 8;

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, getDigestSize() * 8, purpose));

        init(null);
    }

    /**
     * Constructor.
     *
     * @param pSource the source digest.
     */
    public Blake3Digest(final Blake3Digest pSource)
    {
        /* Copy default digest length */
        theDigestLen = pSource.theDigestLen;
        purpose = pSource.purpose;

        /* Initialise from source */
        reset(pSource);
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
     *
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
            Arrays.fill(myKey, (byte)0);

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
            Arrays.fill(theBuffer, (byte)0);
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
                /* Copy data into buffer and return */
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
            Arrays.fill(theBuffer, (byte)0);
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
        if (pOutOffset > (pOut.length - pOutLen))
        {
            throw new OutputLengthException("output buffer too short");
        }

        /* If we have not started outputting yet */
        if (!outputting)
        {
            /* Process the buffer */
            compressFinalBlock(thePos);
        }

        /* Reject if there is insufficient Xof remaining */
        if (pOutLen < 0
            || (outputAvailable >= 0 && pOutLen > outputAvailable))
        {
            throw new IllegalArgumentException("Insufficient bytes remaining");
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

        /* Adjust outputAvailable */
        outputAvailable -= pOutLen;

        /* Return the number of bytes transferred */
        return pOutLen;
    }

    public void reset()
    {
        resetBlockCount();
        thePos = 0;
        outputting = false;
        Arrays.fill(theBuffer, (byte)0);
    }

    public void reset(final Memoable pSource)
    {
        /* Access source */
        final Blake3Digest mySource = (Blake3Digest)pSource;

        /*  Reset counter */
        theCounter = mySource.theCounter;
        theCurrBytes = mySource.theCurrBytes;
        theMode = mySource.theMode;

        /* Reset output state */
        outputting = mySource.outputting;
        outputAvailable = mySource.outputAvailable;
        theOutputMode = mySource.theOutputMode;
        theOutputDataLen = mySource.theOutputDataLen;

        /* Copy state */
        System.arraycopy(mySource.theChaining, 0, theChaining, 0, theChaining.length);
        System.arraycopy(mySource.theK, 0, theK, 0, theK.length);
        System.arraycopy(mySource.theM, 0, theM, 0, theM.length);

        /* Copy stack */
        theStack.clear();
        for (Iterator it = mySource.theStack.iterator(); it.hasNext(); )
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
     *
     * @param pMessage the message buffer
     * @param pMsgPos  the position within the message buffer
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
     *
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
     * Perform compression: the seven rounds of the BLAKE3 compression function over theV, with the message words in
     * theM, followed by the output transformation.
     * <p>
     * The state and message are worked on in local variables, with the fixed message permutation applied to them
     * between rounds, so that C2 can keep them in registers; theV receives the final state and theM is left
     * unchanged.
     * </p>
     */
    private void compress()
    {
        final int[] v = theV, m = theM;

        int v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3], v4 = v[4], v5 = v[5], v6 = v[6], v7 = v[7];
        int v8 = v[8], v9 = v[9], v10 = v[10], v11 = v[11], v12 = v[12], v13 = v[13], v14 = v[14], v15 = v[15];

        int m0 = m[0], m1 = m[1], m2 = m[2], m3 = m[3], m4 = m[4], m5 = m[5], m6 = m[6], m7 = m[7];
        int m8 = m[8], m9 = m[9], m10 = m[10], m11 = m[11], m12 = m[12], m13 = m[13], m14 = m[14], m15 = m[15];

        for (int round = 0; round < ROUNDS; round++)
        {
            /* Apply to columns of V */
            v0 += v4 + m0; v12 = Integers.rotateRight(v12 ^ v0, 16); v8 += v12; v4 = Integers.rotateRight(v4 ^ v8, 12);
            v0 += v4 + m1; v12 = Integers.rotateRight(v12 ^ v0, 8); v8 += v12; v4 = Integers.rotateRight(v4 ^ v8, 7);

            v1 += v5 + m2; v13 = Integers.rotateRight(v13 ^ v1, 16); v9 += v13; v5 = Integers.rotateRight(v5 ^ v9, 12);
            v1 += v5 + m3; v13 = Integers.rotateRight(v13 ^ v1, 8); v9 += v13; v5 = Integers.rotateRight(v5 ^ v9, 7);

            v2 += v6 + m4; v14 = Integers.rotateRight(v14 ^ v2, 16); v10 += v14; v6 = Integers.rotateRight(v6 ^ v10, 12);
            v2 += v6 + m5; v14 = Integers.rotateRight(v14 ^ v2, 8); v10 += v14; v6 = Integers.rotateRight(v6 ^ v10, 7);

            v3 += v7 + m6; v15 = Integers.rotateRight(v15 ^ v3, 16); v11 += v15; v7 = Integers.rotateRight(v7 ^ v11, 12);
            v3 += v7 + m7; v15 = Integers.rotateRight(v15 ^ v3, 8); v11 += v15; v7 = Integers.rotateRight(v7 ^ v11, 7);

            /* Apply to diagonals of V */
            v0 += v5 + m8; v15 = Integers.rotateRight(v15 ^ v0, 16); v10 += v15; v5 = Integers.rotateRight(v5 ^ v10, 12);
            v0 += v5 + m9; v15 = Integers.rotateRight(v15 ^ v0, 8); v10 += v15; v5 = Integers.rotateRight(v5 ^ v10, 7);

            v1 += v6 + m10; v12 = Integers.rotateRight(v12 ^ v1, 16); v11 += v12; v6 = Integers.rotateRight(v6 ^ v11, 12);
            v1 += v6 + m11; v12 = Integers.rotateRight(v12 ^ v1, 8); v11 += v12; v6 = Integers.rotateRight(v6 ^ v11, 7);

            v2 += v7 + m12; v13 = Integers.rotateRight(v13 ^ v2, 16); v8 += v13; v7 = Integers.rotateRight(v7 ^ v8, 12);
            v2 += v7 + m13; v13 = Integers.rotateRight(v13 ^ v2, 8); v8 += v13; v7 = Integers.rotateRight(v7 ^ v8, 7);

            v3 += v4 + m14; v14 = Integers.rotateRight(v14 ^ v3, 16); v9 += v14; v4 = Integers.rotateRight(v4 ^ v9, 12);
            v3 += v4 + m15; v14 = Integers.rotateRight(v14 ^ v3, 8); v9 += v14; v4 = Integers.rotateRight(v4 ^ v9, 7);

            /*
             * Permute the message words for the next round: m'[i] = m[SIGMA[i]], with the BLAKE3 message
             * permutation SIGMA = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}.
             */
            final int t0 = m0, t1 = m1, t2 = m2, t3 = m3, t4 = m4, t5 = m5, t6 = m6, t7 = m7;
            final int t8 = m8, t9 = m9, t10 = m10, t11 = m11, t12 = m12, t13 = m13, t14 = m14, t15 = m15;
            m0 = t2; m1 = t6; m2 = t3; m3 = t10; m4 = t7; m5 = t0; m6 = t4; m7 = t13;
            m8 = t1; m9 = t11; m10 = t12; m11 = t5; m12 = t9; m13 = t14; m14 = t15; m15 = t8;
        }

        v[0] = v0; v[1] = v1; v[2] = v2; v[3] = v3; v[4] = v4; v[5] = v5; v[6] = v6; v[7] = v7;
        v[8] = v8; v[9] = v9; v[10] = v10; v[11] = v11; v[12] = v12; v[13] = v13; v[14] = v14; v[15] = v15;

        adjustChaining();
    }

    /**
     * Initialise M from message.
     *
     * @param pMessage the source message
     * @param pMsgPos  the message position
     */
    private void initM(final byte[] pMessage,
                       final int pMsgPos)
    {
        /* Copy message bytes into word array */
        Pack.littleEndianToInt(pMessage, pMsgPos, theM);
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
            Pack.intToLittleEndian(theV, theBuffer, 0);
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
     * Initialise null key.
     */
    private void initNullKey()
    {
        System.arraycopy(IV, 0, theK, 0, NUMWORDS);
    }

    /**
     * Initialise key.
     *
     * @param pKey the keyBytes
     */
    private void initKey(final byte[] pKey)
    {
        /* Copy message bytes into word array */
        Pack.littleEndianToInt(pKey, 0, theK);
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
     *
     * @param pDataLen the dataLength
     * @param pFinal   is this the final chunk?
     */
    private void initChunkBlock(final int pDataLen,
                                final boolean pFinal)
    {
        /* Initialise the block */
        System.arraycopy(theCurrBytes == 0 ? theK : theChaining, 0, theV, 0, NUMWORDS);
        System.arraycopy(IV, 0, theV, NUMWORDS, NUMWORDS >> 1);
        theV[COUNT0] = (int)theCounter;
        theV[COUNT1] = (int)(theCounter >> Integers.SIZE);
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
        theV[COUNT0] = (int)theCounter;
        theV[COUNT1] = (int)(theCounter >> Integers.SIZE);
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
        outputAvailable = -1;
        System.arraycopy(theV, 0, theChaining, 0, NUMWORDS);
    }

}
