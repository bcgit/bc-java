package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;

public abstract class AbstractTlsKeyExchange implements TlsKeyExchange {

    protected TlsContext context;

    public void init(TlsContext context) {
        this.context = context;
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException {
        processServerCertificate(serverCredentials.getCertificate());
    }

    public boolean requiresServerKeyExchange() {
        return false;
    }

    public byte[] generateServerKeyExchange() throws IOException {
        if (requiresServerKeyExchange()) {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        return null;
    }

    public void skipServerKeyExchange() throws IOException {
        if (requiresServerKeyExchange()) {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void processServerKeyExchange(InputStream is) throws IOException {
        if (!requiresServerKeyExchange()) {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void skipClientCredentials() throws IOException {
    }

    public void processClientCertificate(Certificate clientCertificate) throws IOException {
    }

    public void processClientKeyExchange(InputStream input) throws IOException {
        // Key exchange implementation MUST support client key exchange
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
