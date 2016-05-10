package com.github.gv2011.bcasn.crypto.tls;

import java.io.IOException;

public interface TlsSignerCredentials
    extends TlsCredentials
{
    byte[] generateCertificateSignature(byte[] hash)
        throws IOException;

    SignatureAndHashAlgorithm getSignatureAndHashAlgorithm();
}
