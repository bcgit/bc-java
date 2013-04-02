package org.bouncycastle.crypto.tls;

abstract class AbstractTlsSigner implements TlsSigner {

    protected TlsContext context;

    public void init(TlsContext context) {
        this.context = context;
    }
}
