package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Vector;

import javax.net.ssl.SSLSession;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedAgreement;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedDecryptor;

class ProvTlsServer
    extends DefaultTlsServer
    implements ProvTlsPeer
{
    protected final ProvTlsManager manager;
    protected final ProvSSLParameters sslParameters;

    protected boolean handshakeComplete = false;

    ProvTlsServer(ProvTlsManager manager)
    {
        super(manager.getContextData().getCrypto());

        this.manager = manager;
        this.sslParameters = manager.getProvSSLParameters();
    }

    public synchronized boolean isHandshakeComplete()
    {
        return handshakeComplete;
    }

    public TlsCredentials getCredentials()
        throws IOException
    {
        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.ECDH_anon:
            return null;

        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.RSA:
            break;

        default:
            /* Note: internal error here; selected a key exchange we don't implement! */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        X509KeyManager km = manager.getContextData().getKeyManager();
        if (km == null)
        {
            return null;
        }

        String keyType = JsseUtils.getAuthType(keyExchangeAlgorithm);
        // TODO[jsse] Is there some extension where the client can specify these (SNI maybe)?
        Principal[] issuers = null;
        // TODO[jsse] How is this used?
        Socket socket = null;

        String alias = km.chooseServerAlias(keyType, issuers, socket);
        if (alias == null)
        {
            return null;
        }

        TlsCrypto crypto = getCrypto();
        if (!(crypto instanceof JcaTlsCrypto))
        {
            // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
            throw new UnsupportedOperationException();
        }

        PrivateKey privateKey = km.getPrivateKey(alias);
        Certificate certificate = JsseUtils.getCertificateMessage(crypto, km.getCertificateChain(alias));

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        {
            // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
            return new JceDefaultTlsCredentialedAgreement((JcaTlsCrypto)crypto, certificate, privateKey);
        }

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        {
            short signatureAlgorithm = TlsUtils.getSignatureAlgorithm(keyExchangeAlgorithm);
            SignatureAndHashAlgorithm sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(context,
                supportedSignatureAlgorithms, signatureAlgorithm);

            // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
            return new JcaDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), (JcaTlsCrypto)crypto,
                privateKey, certificate, sigAlg);
        }

        case KeyExchangeAlgorithm.RSA:
        {
            // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
            return new JceDefaultTlsCredentialedDecryptor((JcaTlsCrypto)crypto, certificate, privateKey);
        }

        default:
            /* Note: internal error here; selected a key exchange we don't implement! */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public int[] getCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(manager.getContextData().getCrypto(),
            manager.getContext().convertCipherSuites(sslParameters.getCipherSuites()));
    }

//  public TlsKeyExchange getKeyExchange() throws IOException
//  {
//      // TODO[jsse] Check that all key exchanges used in JSSE supportedCipherSuites are handled
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
        X509TrustManager tm = manager.getContextData().getTrustManager();
        if (tm != null)
        {
            for (X509Certificate caCert : tm.getAcceptedIssuers())
            {
                certificateAuthorities.addElement(X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded()));
            }
        }

        return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
    }

//    @Override
//    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
//    {
//        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
//        out.println("JSSE server raised alert: " + AlertLevel.getText(alertLevel)
//            + ", " + AlertDescription.getText(alertDescription));
//        if (message != null)
//        {
//            out.println("> " + message);
//        }
//        if (cause != null)
//        {
//            cause.printStackTrace(out);
//        }
//    }

    @Override
    public ProtocolVersion getServerVersion() throws IOException
    {
        /*
         * TODO[jsse] It may be best to just require the "protocols" list to be a contiguous set
         * (especially in light of TLS_FALLBACK_SCSV), then just determine the minimum/maximum,
         * and keep the super class implementation of this. 
         */
        String[] protocols = sslParameters.getProtocols();
        if (protocols != null && protocols.length > 0)
        {
            for (ProtocolVersion version = clientVersion; version != null; version = version.getPreviousVersion())
            {
                String versionString = manager.getContext().getProtocolString(version);
                if (versionString != null && JsseUtils.contains(protocols, versionString))
                {
                    return serverVersion = version;
                }
            }
        }
        throw new TlsFatalAlert(AlertDescription.protocol_version);
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

            if (!manager.isClientTrusted(chain, authType))
            {
                /*
                 * TODO[jsse] The low-level TLS API currently doesn't provide a way to indicate that
                 * we wish to proceed with an untrusted client certificate, so we always fail here.
                 */
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }
        }
    }

    @Override
    public synchronized void notifyHandshakeComplete() throws IOException
    {
        this.handshakeComplete = true;

        ProvSSLSessionContext sessionContext = manager.getContextData().getServerSessionContext();
        SSLSession session = sessionContext.reportSession(context.getSession());

        manager.notifyHandshakeComplete(session);
    }
}
