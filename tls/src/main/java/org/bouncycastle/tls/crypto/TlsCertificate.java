package org.bouncycastle.tls.crypto;

import java.io.IOException;

public interface TlsCertificate
{
    short getCertificateType();

    byte[] getEncoded() throws IOException;

    boolean hasKeyUsage(int keyUsage);
}
