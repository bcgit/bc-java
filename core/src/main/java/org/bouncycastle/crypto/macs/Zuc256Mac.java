package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.Zuc256CoreEngine;

/**
 * Zuc256 Mac implementation.
 * Based on https://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180126529970733243.pdf
 */
public final class Zuc256Mac
    implements Mac
{
    /**
     * The Maximum Bit Mask.
     */
    private static final int TOPBIT = 0x80;

    /**
     * The Zuc256 Engine.
     */
    private final InternalZuc256Engine theEngine;

    /**
     * The mac length.
     */
    private final int theMacLength;

    /**
     * The calculated Mac in words.
     */
    private final int[] theMac;

    /**
     * The active keyStream.
     */
    private final int[] theKeyStream;

    /**
     * The initialised state.
     */
    private Zuc256CoreEngine theState;

    /**
     * The current word index.
     */
    private int theWordIndex;

    /**
     * The current byte index.
     */
    private int theByteIndex;

    /**
     * Constructor.
     *
     * @param pLength the bit length of the Mac
     */
    public Zuc256Mac(final int pLength)
    {
        theEngine = new InternalZuc256Engine(pLength);
        theMacLength = pLength;
        final int numWords = pLength / 32; // Integer.SIZE
        theMac = new int[numWords];
        theKeyStream = new int[numWords + 1];
    }

    /**
     * Obtain Algorithm Name.
     *
     * @return the name
     */
    public String getAlgorithmName()
    {
        return "Zuc256Mac-" + theMacLength;
    }

    /**
     * Obtain Mac Size.
     *
     * @return the size in Bytes
     */
    public int getMacSize()
    {
        return theMacLength / 8; //Byte.SIZE
    }

    /**
     * Initialise the Mac.
     *
     * @param pParams the parameters
     */
    public void init(final CipherParameters pParams)
    {
        /* Initialise the engine */
        theEngine.init(true, pParams);
        theState = (Zuc256CoreEngine)theEngine.copy();
        initKeyStream();
    }

    /**
     * Initialise the keyStream.
     */
    private void initKeyStream()
    {
        /* Initialise the Mac */
        for (int i = 0; i < theMac.length; i++)
        {
            theMac[i] = theEngine.createKeyStreamWord();
        }

        /* Initialise the KeyStream */
        for (int i = 0; i < theKeyStream.length - 1; i++)
        {
            theKeyStream[i] = theEngine.createKeyStreamWord();
        }
        theWordIndex = theKeyStream.length - 1;
        theByteIndex = 4 - 1;    // Integer.SIZE
    }

    /**
     * Update the mac with a single byte.
     *
     * @param in the byte to update with
     */
    public void update(final byte in)
    {
        /* shift for next byte */
        shift4NextByte();

        /* Loop through the bits */
        final int bitBase = theByteIndex * 8; //Byte.SIZE;
        for (int bitMask = TOPBIT, bitNo = 0; bitMask > 0; bitMask >>= 1, bitNo++)
        {
            /* If the bit is set */
            if ((in & bitMask) != 0)
            {
                /* update theMac */
                updateMac(bitBase + bitNo);
            }
        }
    }

    /**
     * Shift for next byte.
     */
    private void shift4NextByte()
    {
        /* Adjust the byte index */
        theByteIndex = (theByteIndex + 1) % 4; //Integer.BYTES

        /* Adjust keyStream if required */
        if (theByteIndex == 0)
        {
            theKeyStream[theWordIndex] = theEngine.createKeyStreamWord();
            theWordIndex = (theWordIndex + 1) % theKeyStream.length;
        }
    }

    /**
     * Shift for final update.
     */
    private void shift4Final()
    {
        /* Adjust the byte index */
        theByteIndex = (theByteIndex + 1) % 4; //Integer.BYTES

        /* No need to read another word to the keyStream */
        if (theByteIndex == 0)
        {
            theWordIndex = (theWordIndex + 1) % theKeyStream.length;
        }
    }

    /**
     * Update the Mac.
     *
     * @param bitNo the bit number
     */
    private void updateMac(final int bitNo)
    {
        /* Loop through the Mac */
        for (int wordNo = 0; wordNo < theMac.length; wordNo++)
        {
            theMac[wordNo] ^= getKeyStreamWord(wordNo, bitNo);
        }
    }

    /**
     * Obtain the keyStreamWord.
     *
     * @param wordNo the wordNumber
     * @param bitNo  the bitNumber
     * @return the word
     */
    private int getKeyStreamWord(final int wordNo, final int bitNo)
    {
        /* Access the first word and return it if this is bit 0 */
        final int myFirst = theKeyStream[(theWordIndex + wordNo) % theKeyStream.length];
        if (bitNo == 0)
        {
            return myFirst;
        }

        /* Access the second word */
        final int mySecond = theKeyStream[(theWordIndex + wordNo + 1) % theKeyStream.length];
        return (myFirst << bitNo) | (mySecond >>> (32 - bitNo)); //Integer.SIZE - bitNo
    }

    /**
     * Update the mac.
     *
     * @param in    the input buffer
     * @param inOff the starting offset in the input buffer
     * @param len   the length of data to process
     */
    public void update(final byte[] in, final int inOff, final int len)
    {
        for (int byteNo = 0; byteNo < len; byteNo++)
        {
            update(in[inOff + byteNo]);
        }
    }

    /**
     * Finalize the mac.
     *
     * @param out    the output buffer
     * @param outOff the starting offset in the output buffer
     * @return the size of the mac
     */
    public int doFinal(final byte[] out, final int outOff)
    {
        /* shift for final update */
        shift4Final();

        /* Finish the Mac and output it */
        updateMac(theByteIndex * 8); //Byte.SIZE)
        for (int i = 0; i < theMac.length; i++)
        {
            Zuc256CoreEngine.encode32be(theMac[i], out, outOff + i * 4); //Integer.BYTES)
        }

        /* Reset the Mac */
        reset();
        return getMacSize();
    }

    /**
     * Reset the Mac.
     */
    public void reset()
    {
        if (theState != null)
        {
            theEngine.reset(theState);
        }
        initKeyStream();
    }

    private static class InternalZuc256Engine
        extends Zuc256CoreEngine
    {
        public InternalZuc256Engine(int pLength)
        {
            super(pLength);
        }

        int createKeyStreamWord()
        {
            return super.makeKeyStreamWord();
        }
    }
}
