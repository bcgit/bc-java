package org.bouncycastle.openpgp.operator;

import java.io.OutputStream;

import org.bouncycastle.bcpg.HashAlgorithmTags;

/**
 * A digest calculator, which consumes a stream of data and computes a digest value over it.
 */
public interface PGPDigestCalculator
{
    /**
     * Return the {@link HashAlgorithmTags algorithm number} representing the digest implemented by
     * this calculator.
     * 
     * @return the hash algorithm number
     */
    int getAlgorithm();

    /**
     * Returns a stream that will accept data for the purpose of calculating a digest. Use
     * org.bouncycastle.util.io.TeeOutputStream if you want to accumulate the data on the fly as
     * well.
     * 
     * @return an OutputStream that data to be digested can be written to.
     */
    OutputStream getOutputStream();

    /**
     * Return the digest calculated on what has been written to the calculator's output stream.
     *
     * @return a digest.
     */
    byte[] getDigest();

    /**
     * Reset the underlying digest calculator
     */
    void reset();
}
