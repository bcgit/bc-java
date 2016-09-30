package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509ExtendedKeyManager;

import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.TlsCredentials;

class ProvTlsServer
    extends DefaultTlsServer
    implements TlsProtocolManager
{
    protected final ProvSSLContextSpi context;
    protected final SSLParameters sslParameters;

    protected boolean handshakeComplete = false;

    ProvTlsServer(ProvSSLContextSpi context, SSLParameters sslParameters)
    {
        super(context.getCrypto());
        this.context = context;

        this.sslParameters = sslParameters;
    }

    public synchronized boolean isHandshakeComplete()
    {
        return handshakeComplete;
    }

    public TlsCredentials getCredentials() throws IOException
    {
        // TODO[tls-ops] Locate credentials in configured key stores, suitable for the selected ciphersuite
        X509ExtendedKeyManager km = context.getKeyManager();

        String alias = ""; // TODO: km.chooseServerAlias();

        PrivateKey key = km.getPrivateKey(alias);
        X509Certificate[] certChain = km.getCertificateChain(alias);

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
