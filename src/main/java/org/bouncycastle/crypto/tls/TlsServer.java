package org.bouncycastle.crypto.tls;

import java.io.IOException;

public interface TlsServer {

    void init(TlsServerContext context);

    ProtocolVersion getMaximumVersion();

    ProtocolVersion selectVersion(ProtocolVersion clientVersion) throws IOException;

    TlsCredentials getCredentials();

    TlsKeyExchange getKeyExchange() throws IOException;

    CertificateRequest getCertificateRequest();

    TlsCompression getCompression() throws IOException;

    TlsCipher getCipher() throws IOException;
}
