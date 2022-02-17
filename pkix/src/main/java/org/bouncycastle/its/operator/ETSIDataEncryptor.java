package org.bouncycastle.its.operator;

public interface ETSIDataEncryptor
{
    byte[] encrypt(byte[] content);

    /**
     * return the last key generated
     *
     * @return last key value generated.
     */
    byte[] getKey();

    /**
     * return the last nonce generated
     *
     * @return last nonce value generated.
     */
    byte[] getNonce();
}
