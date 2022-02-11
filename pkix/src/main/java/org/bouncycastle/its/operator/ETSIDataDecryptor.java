package org.bouncycastle.its.operator;

public interface ETSIDataDecryptor
{
    byte[] decrypt(byte[] wrappedKey, byte[] content, byte[] nonce);
}
