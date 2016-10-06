package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Vector;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;

class ProvTlsServer
    extends DefaultTlsServer
    implements TlsProtocolManager
{
    protected final ProvSSLEngine engine;
    protected final SSLParameters sslParameters;

    protected boolean handshakeComplete = false;

    ProvTlsServer(ProvSSLEngine engine)
    {
        super(engine.getContext().getCrypto());

        this.engine = engine;
        this.sslParameters = engine.getSSLParameters();
    }

    public synchronized boolean isHandshakeComplete()
    {
        return handshakeComplete;
    }

    public TlsCredentials getCredentials() throws IOException
    {
        // TODO[tls-ops] Locate credentials in configured key stores, suitable for the selected ciphersuite
        X509KeyManager km = engine.getContext().getX509KeyManager();

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
    public CertificateRequest getCertificateRequest() throws IOException
    {
        boolean shouldRequest = sslParameters.getNeedClientAuth() || sslParameters.getWantClientAuth();
        if (!shouldRequest)
        {
            return null;
        }

        short[] certificateTypes = new short[]{ ClientCertificateType.rsa_sign,
            ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign };

        Vector serverSigAlgs = null;
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion))
        {
            serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms();
        }

        Vector certificateAuthorities = new Vector();
        X509TrustManager tm = engine.getContext().getX509TrustManager();
        if (tm != null)
        {
            for (X509Certificate caCert : tm.getAcceptedIssuers())
            {
                certificateAuthorities.addElement(X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded()));
            }
        }

        return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
    }

    @Override
    public void notifyClientCertificate(Certificate clientCertificate) throws IOException
    {
        // NOTE: This method isn't called unless we returned non-null from getCertificateRequest() earlier
        assert sslParameters.getNeedClientAuth() || sslParameters.getWantClientAuth();

        boolean noClientCert = clientCertificate == null || clientCertificate.isEmpty();
        if (noClientCert)
        {
            if (sslParameters.getNeedClientAuth())
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }
        else
        {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(clientCertificate);
            String authType = JsseUtils.getAuthType(TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite));

            if (engine.isClientTrusted(chain, authType))
            {
                // TODO[jsse] Install client certificate in the session accordingly
            }
            else
            {
                if (sslParameters.getNeedClientAuth())
                {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                // TODO[jsse] Double-check whether to proceed with unauthenticated client
            }
        }
    }

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
