package org.bouncycastle.crypto.paddings;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * A padder that adds the padding according to the scheme referenced in
 * ISO 7814-4 - scheme 2 from ISO 9797-1. The first byte is 0x80, rest is 0x00
 */
public class ISO7816d4Padding
    implements BlockCipherPadding
{
    /**
     * Initialise the padder.
     *
     * @param random - a SecureRandom if available.
     */
    public void init(SecureRandom random)
        throws IllegalArgumentException
    {
        // nothing to do.
    }

    /**
     * Return the name of the algorithm the padder implements.
     *
     * @return the name of the algorithm the padder implements.
     */
    public String getPaddingName()
    {
        return "ISO7816-4";
    }

    /**
     * add the pad bytes to the passed in block, returning the
     * number of bytes added.
     */
    public int addPadding(
        byte[]  in,
        int     inOff)
    {
        int added = (in.length - inOff);

        in [inOff]= (byte) 0x80;
        inOff ++;
        
        while (inOff < in.length)
        {
            in[inOff] = (byte) 0;
            inOff++;
        }

        return added;
    }

    /**
     * return the number of pad bytes present in the block.
     */
    public int padCount(byte[] in)
        throws InvalidCipherTextException
    {
        int position = -1, still00Mask = -1;
        int i = in.length;
        while (--i >= 0)
        {
            int next = in[i] & 0xFF;
            int match00Mask = ((next ^ 0x00) - 1) >> 31;
            int match80Mask = ((next ^ 0x80) - 1) >> 31;
            position ^= (i ^ position) & (still00Mask & match80Mask);
            still00Mask &= match00Mask;
        }
        if (position < 0)
        {
            throw new InvalidCipherTextException("pad block corrupted");
        }
        return in.length - position;
    }
}
