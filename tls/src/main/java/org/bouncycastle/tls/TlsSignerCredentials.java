package org.bouncycastle.tls;

import java.io.IOException;

public interface TlsSignerCredentials
    extends TlsCredentials
{
    byte[] generateRawSignature(byte[] hash)
        throws IOException;

    SignatureAndHashAlgorithm getSignatureAndHashAlgorithm();
}
