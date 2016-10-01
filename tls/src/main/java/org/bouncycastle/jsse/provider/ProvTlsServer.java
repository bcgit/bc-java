package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509ExtendedKeyManager;

import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsSession;

class ProvTlsServer
    extends DefaultTlsServer
    implements TlsProtocolManager
{
    protected final ProvSSLContextSpi sslContext;
    protected final SSLParameters sslParameters;

    protected boolean handshakeComplete = false;

    ProvTlsServer(ProvSSLContextSpi sslContext, SSLParameters sslParameters)
    {
        super(sslContext.getCrypto());

        this.sslContext = sslContext;
        this.sslParameters = sslParameters;
    }

    public synchronized boolean isHandshakeComplete()
    {
        return handshakeComplete;
    }

    public TlsCredentials getCredentials() throws IOException
    {
        // TODO[tls-ops] Locate credentials in configured key stores, suitable for the selected ciphersuite
        X509ExtendedKeyManager km = sslContext.getKeyManager();

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

        TlsSession tlsSession = context.getResumableSession();
        if (tlsSession != null && tlsSession.isResumable())
        {
            // TODO[tls-ops] Register the session with the server SSLSessionContext of our SSLContext
        }
    }
}
