package org.bouncycastle.crypto;

/**
 * Ciphers producing a key stream which can be reset to particular points in the stream.
 */
public interface SkippingCipher
{
    /**
     * Skip numberOfBlocks forwards, or backwards. If the cipher is a stream cipher a block
     * size of 1 is assumed.
     *
     * @param numberOfBlocks the number of blocks to skip (positive forward, negative backwards).
     * @return the number of blocks actually skipped.
     * @throws java.lang.IllegalArgumentException if numberOfBlocks is an invalid value.
     */
    long skip(long numberOfBlocks);
}
