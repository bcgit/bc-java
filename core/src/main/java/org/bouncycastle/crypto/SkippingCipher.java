package org.bouncycastle.crypto;

/**
 * Ciphers producing a keystream which can be moved around
 */
public interface SkippingCipher
{
    /**
     * Skip numberOfBlocks forwards, or backwards. If the cipher is a streamcipher a block
     * size of 1 is assumed.
     *
     * @param numberOfBlocks the number of blocks to skip (positive forward, negative backwards).
     * @return the number of blocks actually skipped.
     */
    long skip(long numberOfBlocks);
}
