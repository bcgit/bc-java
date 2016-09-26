package org.bouncycastle.jsse.provider;

import java.io.IOException;

import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsCrypto;
import org.bouncycastle.tls.TlsKeyExchange;

class ProvTlsServer
    extends DefaultTlsServer
    implements TlsProtocolManager
{
    protected boolean handshakeComplete = false;

    ProvTlsServer(TlsCrypto crypto)
    {
        super(crypto);
    }

    public synchronized boolean isHandshakeComplete()
    {
        return handshakeComplete;
    }

    public TlsCredentials getCredentials() throws IOException
    {
        // TODO[tls-ops] Locate credentials in configured key stores, suitable for the selected ciphersuite

        throw new UnsupportedOperationException();
    }

    public int[] getCipherSuites()
    {
        // TODO[tls-ops] Needs to come from the JSSE enabledCipherSuites

        throw new UnsupportedOperationException();
    }

    public TlsKeyExchange getKeyExchange() throws IOException
    {
        // TODO[tls-ops] Check that all key exchanges used in JSSE supportedCipherSuites are handled
        return super.getKeyExchange();
    }

    @Override
    public synchronized void notifyHandshakeComplete() throws IOException
    {
        this.handshakeComplete = true;
    }
}
