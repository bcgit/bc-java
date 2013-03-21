package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;

public abstract class AbstractTlsKeyExchange implements TlsKeyExchange {

    protected TlsContext context;

    public void init(TlsContext context) {
        this.context = context;
    }

    public boolean requiresServerKeyExchange() {
        return false;
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
}
