package org.bouncycastle.its.operator;

public interface ETSIDataEncryptor
{
    byte[] encrypt(byte[] key, byte[] nonce, byte[] content);
}
