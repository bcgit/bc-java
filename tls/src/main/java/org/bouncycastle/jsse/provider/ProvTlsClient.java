package org.bouncycastle.jsse.provider;

import java.io.IOException;

import javax.net.ssl.SSLParameters;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;

class ProvTlsClient
    extends DefaultTlsClient
    implements TlsProtocolManager
{
    protected final SSLParameters sslParameters;

    protected boolean handshakeComplete = false;

    ProvTlsClient(TlsCrypto crypto, SSLParameters sslParameters)
    {
        super(crypto);

        this.sslParameters = sslParameters;
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

        TlsSession tlsSession = context.getResumableSession();
        if (tlsSession != null && tlsSession.isResumable())
        {
            // TODO[tls-ops] Register the session with the client SSLSessionContext of our SSLContext
        }
    }

    // TODO[tls-ops] Maybe this should live in a utility method in the TLS API.
    protected String getAuthType() throws IOException
    {
        // TODO[tls-ops] Support for full range of key exchange algorithms
        switch (TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite))
        {
        case KeyExchangeAlgorithm.DH_RSA:
            return "DH_RSA";
        case KeyExchangeAlgorithm.DHE_RSA:
            return "DHE_RSA";
        case KeyExchangeAlgorithm.ECDH_RSA:
            return "ECDH_RSA";
        case KeyExchangeAlgorithm.ECDHE_RSA:
            return "ECDHE_RSA";
        case KeyExchangeAlgorithm.RSA:
            return "RSA";
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
