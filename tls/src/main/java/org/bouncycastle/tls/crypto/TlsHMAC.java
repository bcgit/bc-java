package org.bouncycastle.tls.crypto;

public interface TlsHMAC
{
    void setKey(byte[] key);

    void update(byte[] input, int inOff, int length);

    byte[] calculateMAC();

    int getInternalBlockSize();

    int getMacLength();

    void reset();
}
