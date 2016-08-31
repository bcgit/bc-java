package org.bouncycastle.tls.crypto;

public interface TlsHMAC
    extends TlsMAC
{
    int getInternalBlockSize();
}
