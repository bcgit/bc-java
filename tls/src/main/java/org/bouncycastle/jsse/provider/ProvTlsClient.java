package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLParameters;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;

class ProvTlsClient
    extends DefaultTlsClient
    implements TlsProtocolManager
{
    protected final ProvSSLEngine engine;
    protected final SSLParameters sslParameters;

    protected boolean handshakeComplete = false;

    ProvTlsClient(ProvSSLEngine engine)
    {
        super(engine.getContext().getCrypto());

        this.engine = engine;
        this.sslParameters = engine.getSSLParameters();
    }

    public synchronized boolean isHandshakeComplete()
    {
        return handshakeComplete;
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        // TODO[jsse] If client authentication enabled, locate credentials in configured key stores,
        // suitable for the selected ciphersuite

        return new ServerOnlyTlsAuthentication()
        {
            public void notifyServerCertificate(Certificate serverCertificate) throws IOException
            {
                boolean noServerCert = serverCertificate == null || serverCertificate.isEmpty();
                if (noServerCert)
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
                else
                {
                    X509Certificate[] chain = JsseUtils.getX509CertificateChain(serverCertificate);
                    String authType = JsseUtils.getAuthType(TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite));
    
                    if (engine.isServerTrusted(chain, authType))
                    {
                        // TODO[jsse] Install server certificate in the session accordingly
                    }
                    else
                    {
                        throw new TlsFatalAlert(AlertDescription.bad_certificate);
                    }
                }
            }
        };
    }

//    public int[] getCipherSuites()
//    {
//        // TODO[jsse] Needs to come from the JSSE enabledCipherSuites
//        throw new UnsupportedOperationException();
//    }

//    public TlsKeyExchange getKeyExchange() throws IOException
//    {
//        // TODO[jsse] Check that all key exchanges used in JSSE supportedCipherSuites are handled
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
}
