package org.bouncycastle.openssl;

public interface PEMEncryptor
{
    String getAlgorithm();

    byte[] getIV();

    byte[] encrypt(byte[] encoding)
        throws PEMException;
}
