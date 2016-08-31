package org.bouncycastle.tls.crypto;

import java.io.IOException;

public interface TlsSuiteMac
{
    int getSize();

    byte[] calculateMac(long seqNo, short type, byte[] plaintext, int offset, int len);

    byte[] calculateMacConstantTime(long seqNo, short type, byte[] ciphertext, int offset, int macInputLen, int i, byte[] randomData);

    void setKey(byte[] macKey)
        throws IOException;
}
