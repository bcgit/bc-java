package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.io.InputStream;

public interface TlsAgreement
{
    void configureStatic(InputStream input) throws IOException;

    byte[] generateEphemeral() throws IOException;

    void receivePeerValue(byte[] peerValue) throws IOException;

    void usePeerCertificate(TlsCertificate certificate) throws IOException;

    TlsSecret calculateSecret() throws IOException;
}
