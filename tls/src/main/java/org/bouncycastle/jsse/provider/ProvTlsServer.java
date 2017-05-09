package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLSession;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
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
    private static Logger LOG = Logger.getLogger(ProvTlsServer.class.getName());

    protected final ProvTlsManager manager;
    protected final ProvSSLParameters sslParameters;

    protected Set<String> keyManagerMissCache = null;
    protected TlsCredentials credentials = null;
    protected boolean handshakeComplete = false;

    ProvTlsServer(ProvTlsManager manager)
    {
        super(manager.getContextData().getCrypto());

        this.manager = manager;
        this.sslParameters = manager.getProvSSLParameters();
    }

    protected boolean selectCipherSuite(int cipherSuite) throws IOException
    {
        if (!selectCredentials(cipherSuite))
        {
            return false;
        }

        return super.selectCipherSuite(cipherSuite);
    }

    public synchronized boolean isHandshakeComplete()
    {
        return handshakeComplete;
    }

    public TlsCredentials getCredentials()
        throws IOException
    {
        return credentials;
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
            serverSigAlgs = JsseUtils.getSupportedSignatureAlgorithms(getCrypto());
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

    @Override
    public int getSelectedCipherSuite() throws IOException
    {
        keyManagerMissCache = new HashSet<String>();

        int selectedCipherSuite = super.getSelectedCipherSuite();

        LOG.fine("Server selected cipher suite: " + manager.getContext().getCipherSuiteString(selectedCipherSuite));

        keyManagerMissCache = null;

        return selectedCipherSuite;
    }

    @Override
    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        Level level = alertLevel == AlertLevel.warning                      ? Level.FINE
                    : alertDescription == AlertDescription.internal_error   ? Level.WARNING
                    :                                                         Level.INFO;

        if (LOG.isLoggable(level))
        {
            String msg = JsseUtils.getAlertLogMessage("Server raised", alertLevel, alertDescription);
            if (message != null)
            {
                msg = msg + ": " + message;
            }

            LOG.log(level, msg, cause);
        }
    }

    @Override
    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        super.notifyAlertReceived(alertLevel, alertDescription);

        Level level = alertLevel == AlertLevel.warning  ? Level.FINE
                    :                                     Level.INFO;

        if (LOG.isLoggable(level))
        {
            String msg = JsseUtils.getAlertLogMessage("Server received", alertLevel, alertDescription);

            LOG.log(level, msg);
        }
    }

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
                    LOG.fine("Server selected protocol version: " + version);
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
            short clientCertificateType = clientCertificate.getCertificateAt(0).getClientCertificateType();
            String authType = JsseUtils.getAuthTypeClient(clientCertificateType);

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
        ProvSSLConnection connection = new ProvSSLConnection(context, session);

        manager.notifyHandshakeComplete(connection);
    }

    protected boolean selectCredentials(int cipherSuite) throws IOException
    {
        this.credentials = null;

        int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(cipherSuite);
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.ECDH_anon:
            return true;

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
            return false;
        }

        X509KeyManager km = manager.getContextData().getKeyManager();
        if (km == null)
        {
            return false;
        }

        String keyType = JsseUtils.getAuthTypeServer(keyExchangeAlgorithm);
        if (keyManagerMissCache.contains(keyType))
        {
            return false;
        }

        // TODO[jsse] Is there some extension where the client can specify these (SNI maybe)?
        Principal[] issuers = null;
        // TODO[jsse] How is this used?
        Socket socket = null;

        String alias = km.chooseServerAlias(keyType, issuers, socket);
        if (alias == null)
        {
            keyManagerMissCache.add(keyType);
            return false;
        }

        TlsCrypto crypto = getCrypto();
        if (!(crypto instanceof JcaTlsCrypto))
        {
            // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
            throw new UnsupportedOperationException();
        }

        PrivateKey privateKey = km.getPrivateKey(alias);
        Certificate certificate = JsseUtils.getCertificateMessage(crypto, km.getCertificateChain(alias));

        if (privateKey == null || certificate.isEmpty())
        {
            keyManagerMissCache.add(keyType);
            return false;
        }

        /*
         * TODO[jsse] Before proceeding with EC credentials, should we check (TLS 1.2+) that the
         * used curve is supported by the client according to the elliptic_curves/named_groups
         * extension?
         */
        
        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        {
            // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
            this.credentials = new JceDefaultTlsCredentialedAgreement((JcaTlsCrypto)crypto, certificate, privateKey);
            return true;
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
            this.credentials = new JcaDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), (JcaTlsCrypto)crypto,
                privateKey, certificate, sigAlg);
            return true;
        }

        case KeyExchangeAlgorithm.RSA:
        {
            // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
            this.credentials = new JceDefaultTlsCredentialedDecryptor((JcaTlsCrypto)crypto, certificate, privateKey);
            return true;
        }

        default:
            return false;
        }
    }
}
