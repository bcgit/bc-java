package org.bouncycastle.openssl;

public interface PEMDecryptor
{
    byte[] decrypt(byte[] keyBytes, byte[] iv)
        throws PEMException;
}
