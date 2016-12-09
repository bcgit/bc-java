package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.Vector;

import javax.net.ssl.SSLSession;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedAgreement;

class ProvTlsClient
    extends DefaultTlsClient
    implements ProvTlsPeer
{
    protected final ProvTlsManager manager;
    protected final ProvSSLParameters sslParameters;

    protected boolean handshakeComplete = false;

    ProvTlsClient(ProvTlsManager manager)
    {
        super(manager.getContextData().getCrypto());

        this.manager = manager;
        this.sslParameters = manager.getProvSSLParameters();
    }

    public synchronized boolean isHandshakeComplete()
    {
        return handshakeComplete;
    }

    public TlsAuthentication getAuthentication() throws IOException
    {
        return new TlsAuthentication()
        {
            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException
            {
                // TODO[jsse] What criteria determines whether we are willing to send client authentication?

                int keyExchangeAlgorithm = TlsUtils.getKeyExchangeAlgorithm(selectedCipherSuite);
                switch (keyExchangeAlgorithm)
                {
                case KeyExchangeAlgorithm.DH_DSS:
                case KeyExchangeAlgorithm.DH_RSA:
                case KeyExchangeAlgorithm.ECDH_ECDSA:
                case KeyExchangeAlgorithm.ECDH_RSA:
                    // TODO[jsse] Add support for the static key exchanges
                    return null;

                case KeyExchangeAlgorithm.DHE_DSS:
                case KeyExchangeAlgorithm.DHE_RSA:
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

                short[] certTypes = certificateRequest.getCertificateTypes();
                if (certTypes == null || certTypes.length == 0)
                {
                    // TODO[jsse] Or does this mean ANY type - or something else?
                    return null;
                }

                String[] keyTypes = new String[certTypes.length];
                for (int i = 0; i < certTypes.length; ++i)
                {
                    // TODO[jsse] Need to also take notice of certificateRequest.getSupportedSignatureAlgorithms(), if present
                    keyTypes[i] = JsseUtils.getClientAuthType(certTypes[i]);
                }

                Principal[] issuers = null;
                Vector<X500Name> cas = (Vector<X500Name>)certificateRequest.getCertificateAuthorities();
                if (cas != null && cas.size() > 0)
                {
                	X500Name[] names = cas.toArray(new X500Name[cas.size()]);
                	Set<X500Principal> principals = JsseUtils.toX500Principals(names);
                	issuers = principals.toArray(new Principal[principals.size()]);
                }

                // TODO[jsse] How is this used?
                Socket socket = null;

                String alias = km.chooseClientAlias(keyTypes, issuers, socket);
                if (alias == null)
                {
                    // TODO[jsse] Should sslParameters.getNeedClientAuth imply failing the handshake here?
                    return null;
                }

                TlsCrypto crypto = getCrypto();
                if (!(crypto instanceof JcaTlsCrypto))
                {
                    // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
                    throw new UnsupportedOperationException();
                }

                PrivateKey privateKey = km.getPrivateKey(alias);
                X509Certificate[] chain = km.getCertificateChain(alias);
                Certificate certificate = JsseUtils.getCertificateMessage(crypto, chain);

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
                case KeyExchangeAlgorithm.RSA:
                {
                    short signatureAlgorithm = TlsUtils.getSignatureAlgorithm(keyExchangeAlgorithm);
                    SignatureAndHashAlgorithm sigAlg = TlsUtils.chooseSignatureAndHashAlgorithm(context,
                        supportedSignatureAlgorithms, signatureAlgorithm);

                    // TODO[jsse] Need to have TlsCrypto construct the credentials from the certs/key
                    return new JcaDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), (JcaTlsCrypto)crypto,
                        privateKey, certificate, sigAlg);
                }

                default:
                    /* Note: internal error here; selected a key exchange we don't implement! */
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }
            }

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

                    if (!manager.isServerTrusted(chain, authType))
                    {
                        throw new TlsFatalAlert(AlertDescription.bad_certificate);
                    }
                }
            }
        };
    }

    @Override
    public int[] getCipherSuites()
    {
        return TlsUtils.getSupportedCipherSuites(manager.getContextData().getCrypto(),
            manager.getContext().convertCipherSuites(sslParameters.getCipherSuites()));
    }

//    public TlsKeyExchange getKeyExchange() throws IOException
//    {
//        // TODO[jsse] Check that all key exchanges used in JSSE supportedCipherSuites are handled
//        return super.getKeyExchange();
//    }

    @Override
    public ProtocolVersion getMinimumVersion()
    {
        return manager.getContext().getMinimumVersion(sslParameters.getProtocols());
    }

    @Override
    public ProtocolVersion getClientVersion()
    {
        return manager.getContext().getMaximumVersion(sslParameters.getProtocols());
    }

    @Override
    public TlsSession getSessionToResume()
    {
        // TODO[jsse] Search for a suitable session in the client session context
        return null;
    }

//    @Override
//    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
//    {
//        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
//        out.println("JSSE client raised alert: " + AlertLevel.getText(alertLevel)
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
    public synchronized void notifyHandshakeComplete() throws IOException
    {
        this.handshakeComplete = true;

        ProvSSLSessionContext sessionContext = manager.getContextData().getClientSessionContext();
        SSLSession session = sessionContext.reportSession(context.getSession());

        manager.notifyHandshakeComplete(session);
    }

    @Override
    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        String selected = manager.getContext().getProtocolString(serverVersion);
        if (selected != null)
        {
            for (String protocol : sslParameters.getProtocols())
            {
                if (selected.equals(protocol))
                {
                    return;
                }
            }
        }
        throw new TlsFatalAlert(AlertDescription.protocol_version);
    }
}
