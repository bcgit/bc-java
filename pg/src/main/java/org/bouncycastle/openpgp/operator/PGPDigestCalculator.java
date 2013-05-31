package org.bouncycastle.openpgp.operator;

import java.io.OutputStream;

public interface PGPDigestCalculator
{
    /**
        * Return the algorithm number representing the digest implemented by
        * this calculator.
        *
        * @return algorithm number
        */
    int getAlgorithm();

    /**
        * Returns a stream that will accept data for the purpose of calculating
        * a digest. Use org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
        * the data on the fly as well.
        *
        * @return an OutputStream
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
