package org.bouncycastle.jsse.provider;

import java.io.IOException;

import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsCrypto;

class ProvTlsClient
    extends DefaultTlsClient
    implements TlsProtocolManager
{
    protected boolean handshakeComplete = false;

    ProvTlsClient(TlsCrypto crypto)
    {
        super(crypto);
    }

    public synchronized boolean isHandshakeComplete()
    {
        return handshakeComplete;
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        // TODO[tls-ops] If client authentication enabled, locate credentials in configured key stores,
        // suitable for the selected ciphersuite
        return null;
    }

//    public int[] getCipherSuites()
//    {
//        // TODO[tls-ops] Needs to come from the JSSE enabledCipherSuites
//        throw new UnsupportedOperationException();
//    }

//    public TlsKeyExchange getKeyExchange() throws IOException
//    {
//        // TODO[tls-ops] Check that all key exchanges used in JSSE supportedCipherSuites are handled
//        return super.getKeyExchange();
//    }

    @Override
    public synchronized void notifyHandshakeComplete() throws IOException
    {
        this.handshakeComplete = true;
    }
}
