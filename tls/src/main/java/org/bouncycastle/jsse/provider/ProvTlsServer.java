package org.bouncycastle.jsse.provider;

import java.io.IOException;

import javax.net.ssl.SSLParameters;

import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsCrypto;

class ProvTlsServer
    extends DefaultTlsServer
    implements TlsProtocolManager
{
    protected final SSLParameters sslParameters;

    protected boolean handshakeComplete = false;

    ProvTlsServer(TlsCrypto crypto, SSLParameters sslParameters)
    {
        super(crypto);

        this.sslParameters = sslParameters;
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

//  public int[] getCipherSuites()
//  {
//      // TODO[tls-ops] Needs to come from the JSSE enabledCipherSuites
//      throw new UnsupportedOperationException();
//  }

//  public TlsKeyExchange getKeyExchange() throws IOException
//  {
//      // TODO[tls-ops] Check that all key exchanges used in JSSE supportedCipherSuites are handled
//      return super.getKeyExchange();
//  }

    @Override
    public synchronized void notifyHandshakeComplete() throws IOException
    {
        this.handshakeComplete = true;
    }
}
