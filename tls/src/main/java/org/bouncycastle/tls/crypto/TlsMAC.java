package org.bouncycastle.tls.crypto;

public interface TlsMAC
{
    void setKey(byte[] key);

    void update(byte[] input, int inOff, int length);

    byte[] calculateMAC();

    int getMacLength();

    void reset();
}
