package org.bouncycastle.openpgp.operator;

import java.io.OutputStream;

public interface PGPContentSigner
{
    public OutputStream getOutputStream();

    byte[] getSignature();

    byte[] getDigest();

    int getType();

    int getHashAlgorithm();

    int getKeyAlgorithm();

    long getKeyID();
}
