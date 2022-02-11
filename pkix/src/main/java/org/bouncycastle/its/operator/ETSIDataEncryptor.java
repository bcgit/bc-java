package org.bouncycastle.its.operator;

public interface ETSIDataEncryptor
{
    byte[] encrypt(byte[] key, byte[] content);

    /**
     * return the last nonce generated
     * @return last nonce value generated.
     */
    byte[] getNonce();
}
