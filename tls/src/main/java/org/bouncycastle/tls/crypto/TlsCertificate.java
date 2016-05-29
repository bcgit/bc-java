package org.bouncycastle.tls.crypto;

public interface TlsCertificate
{
    boolean hasKeyUsage(int keyUsage);
}
