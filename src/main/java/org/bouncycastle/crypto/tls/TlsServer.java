package org.bouncycastle.crypto.tls;

public interface TlsServer {

    void init(TlsServerContext context);

    CertificateRequest getCertificateRequest();
}
