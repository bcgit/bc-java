package org.bouncycastle.crypto.tls;

import java.io.IOException;

public interface TlsServer {

    void init(TlsServerContext context);

    TlsCredentials getCredentials();

    TlsKeyExchange getKeyExchange() throws IOException;

    CertificateRequest getCertificateRequest();
}
