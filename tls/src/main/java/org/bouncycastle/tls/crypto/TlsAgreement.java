package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface TlsAgreement
{
    void configureStatic(InputStream input) throws IOException;

    void generateEphemeral(OutputStream output) throws IOException;

    void receivePeerValue(InputStream input) throws IOException;

    TlsSecret calculateSecret() throws IOException;
}
