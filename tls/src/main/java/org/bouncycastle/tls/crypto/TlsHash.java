package org.bouncycastle.tls.crypto;

public interface TlsHash
{
    void update(byte[] data, int offSet, int length);

    byte[] calculateHash();

    TlsHash cloneHash(); // TODO: change to clone() when properly added

    void reset();
}
