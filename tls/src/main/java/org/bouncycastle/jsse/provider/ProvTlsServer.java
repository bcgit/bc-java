package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
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
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

class ProvTlsServer
    extends DefaultTlsServer
    implements ProvTlsPeer
{
    protected static short MINIMUM_HASH_STRICT = HashAlgorithm.sha1;
    protected static short MINIMUM_HASH_PREFERRED = HashAlgorithm.sha256;

    protected final ProvTlsManager manager;
    protected final SSLParameters sslParameters;

    protected boolean handshakeComplete = false;

    ProvTlsServer(ProvTlsManager manager)
    {
        super(manager.getContext().getCrypto());

        this.manager = manager;
        this.sslParameters = manager.getSSLParameters();
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

        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        case KeyExchangeAlgorithm.RSA:
            break;

        default:
            /* Note: internal error here; selected a key exchange we don't implement! */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        X509KeyManager km = manager.getContext().getX509KeyManager();
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
            // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key
            throw new UnsupportedOperationException();
        }

        PrivateKey privateKey = km.getPrivateKey(alias);
        Certificate certificate = JsseUtils.getCertificateMessage(crypto, km.getCertificateChain(alias));

        switch (keyExchangeAlgorithm)
        {
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.DHE_RSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
        {
            short signatureAlgorithm = TlsUtils.getSignatureAlgorithm(keyExchangeAlgorithm);
            SignatureAndHashAlgorithm sigAlg = chooseSignatureAndHashAlgorithm(signatureAlgorithm);

            // TODO[tls-ops] Need to have TlsCrypto construct the credentials from the certs/key
            return new JcaDefaultTlsCredentialedSigner(new TlsCryptoParameters(context), (JcaTlsCrypto)crypto,
                privateKey, certificate, sigAlg);
        }

        case KeyExchangeAlgorithm.RSA:
        {
            // TODO[tls-ops] Missing JceDefaultTlsCredentialedEncryptor?
            throw new UnsupportedOperationException();
        }

        default:
            /* Note: internal error here; selected a key exchange we don't implement! */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public int[] getCipherSuites()
    {
        return manager.getContext().convertCipherSuites(sslParameters.getCipherSuites());
    }

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
        X509TrustManager tm = manager.getContext().getX509TrustManager();
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

            if (manager.isClientTrusted(chain, authType))
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

    // TODO[tls-ops] Consider moving this to TlsUtils
    protected SignatureAndHashAlgorithm chooseSignatureAndHashAlgorithm(int signatureAlgorithm)
        throws IOException
    {
        if (!TlsUtils.isTLSv12(context))
        {
            return null;
        }

        Vector algs = supportedSignatureAlgorithms;
        if (algs == null)
        {
            algs = TlsUtils.getDefaultSignatureAlgorithms(signatureAlgorithm);
        }

        SignatureAndHashAlgorithm result = null;
        for (int i = 0; i < algs.size(); ++i)
        {
            SignatureAndHashAlgorithm alg = (SignatureAndHashAlgorithm)algs.elementAt(i);
            if (alg.getSignature() == signatureAlgorithm)
            {
                short hash = alg.getHash();
                if (result == null)
                {
                    if (hash >= MINIMUM_HASH_STRICT)
                    {
                        result = alg;
                    }
                }
                else
                {
                    short current = result.getHash();
                    if (current < MINIMUM_HASH_PREFERRED)
                    {
                        if (hash > current)
                        {
                            result = alg;
                        }
                    }
                    else
                    {
                        if (hash < current)
                        {
                            result = alg;
                        }
                    }
                }
            }
        }
        if (result == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        return result;
    }
}
