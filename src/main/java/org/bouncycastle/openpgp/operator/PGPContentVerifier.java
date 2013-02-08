package org.bouncycastle.openpgp.operator;

import java.io.OutputStream;

public interface PGPContentVerifier
{
    public OutputStream getOutputStream();

    int getHashAlgorithm();

    int getKeyAlgorithm();

    long getKeyID();

    /**
     * @param expected expected value of the signature on the data.
     * @return true if the signature verifies, false otherwise
     */
    boolean verify(byte[] expected);
}
