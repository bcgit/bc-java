package org.bouncycastle.est.jcajce;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CRL;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.est.ESTClient;
import org.bouncycastle.est.ESTClientProvider;
import org.bouncycastle.est.ESTException;

public class JcaDefaultESTHttpClientProvider
    implements ESTClientProvider
{

    private final Set<TrustAnchor> tlsTrustAnchors;
    private final KeyStore clientKeystore;
    private final char[] clientKeystorePassword;
    private final JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    private final CRL[] revocationLists;
    private final JcaJceAuthorizer estAuthorizer;
    private final String tlsVersion;

    public JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors,
                                           KeyStore clientKeystore,
                                           char[] clientKeystorePassword,
                                           JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer,
                                           CRL[] revocationLists, JcaJceAuthorizer estAuthorizer, String tlsVersion)
    {
        this.tlsTrustAnchors = tlsTrustAnchors;
        this.clientKeystore = clientKeystore;
        this.clientKeystorePassword = clientKeystorePassword;
        this.hostNameAuthorizer = hostNameAuthorizer;
        this.revocationLists = revocationLists;
        this.estAuthorizer = estAuthorizer;
        this.tlsVersion = tlsVersion;
    }

    public ESTClient makeClient()
        throws ESTException
    {


        try
        {
            KeyManagerFactory keyFact = null;
            if (clientKeystore != null)
            {
                keyFact = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyFact.init(clientKeystore, clientKeystorePassword);
            }

            JcaJceAuthorizer estAuthorizer = this.estAuthorizer;

            SSLSocketFactory socketFactory = null;

            if (tlsTrustAnchors == null && estAuthorizer == null)
            {
                socketFactory = (SSLSocketFactory)createFactory(tlsVersion, null, null);
            }
            else if (tlsTrustAnchors != null && estAuthorizer == null)
            {
                estAuthorizer = DefaultESTClientSourceProvider.getCertPathTLSAuthorizer(revocationLists, tlsTrustAnchors);
            }
            if (socketFactory == null)
            {
                socketFactory = createFactory(tlsVersion, keyFact, estAuthorizer);
            }
            return new DefaultESTClient(
                new DefaultESTClientSourceProvider(socketFactory, hostNameAuthorizer));
        }
        catch (GeneralSecurityException e)
        {
            throw new ESTException(e.getMessage(), e.getCause());
        }
    }

    public SSLSocketFactory createFactory(String tlsVersion, KeyManagerFactory keyManagerFactory, final JcaJceAuthorizer estAuthorizer)
        throws GeneralSecurityException
    {
        SSLContext ctx = SSLContext.getInstance(tlsVersion);

        if (keyManagerFactory == null && estAuthorizer == null)
        {
            ctx.init(null, null, new SecureRandom());
            return ctx.getSocketFactory();
        }


        X509TrustManager tm = new X509TrustManager()
        {
            public void checkClientTrusted(X509Certificate[] x509Certificates, String authType)
                throws CertificateException
            {
                // For clients.
            }

            public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
                throws CertificateException
            {
                if (estAuthorizer == null)
                {
                    throw new CertificateException(
                        "No serverTLSAuthorizer specified, if you wish to have no validation then you must supply an instance that does nothing."
                    );
                }

                estAuthorizer.authorize(x509Certificates, s);
            }

            public X509Certificate[] getAcceptedIssuers()
            {
                if (tlsTrustAnchors != null)
                {
                    Set<TrustAnchor> tas = tlsTrustAnchors;
                    X509Certificate[] c = new X509Certificate[tas.size()];
                    int j = 0;
                    for (Iterator it = tas.iterator(); it.hasNext(); )
                    {
                        TrustAnchor ta = (TrustAnchor)it.next();
                        c[j++] = ta.getTrustedCert();
                    }
                    return c;
                }
                return new X509Certificate[0];
            }
        };

        ctx.init((keyManagerFactory != null) ? keyManagerFactory.getKeyManagers() : null, new TrustManager[]{tm}, new SecureRandom());
        return ctx.getSocketFactory();

    }

    public boolean isTrusted()
    {
        return tlsTrustAnchors != null && !tlsTrustAnchors.isEmpty();
    }
}
