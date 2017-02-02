package org.bouncycastle.est;

import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.TrustAnchor;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSession;

import org.bouncycastle.est.http.DefaultESTClient;
import org.bouncycastle.est.http.DefaultESTClientSSLSocketProvider;
import org.bouncycastle.est.http.ESTHttpClient;
import org.bouncycastle.est.http.TLSAcceptedIssuersSource;
import org.bouncycastle.est.http.TLSAuthorizer;
import org.bouncycastle.est.http.TLSHostNameAuthorizer;

/**
 * Build a RFC7030 client.
 */
public class ESTServiceBuilder
{
    protected Set<TrustAnchor> tlsTrustAnchors;
    protected KeyStore clientKeystore;
    protected char[] clientKeystorePassword;
    protected TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    final protected String server;
    protected TLSAuthorizer<SSLSession> tlsAuthorizer;
    protected CRL revocationList;
    protected ESTHttpClientProvider clientProvider;

    public ESTServiceBuilder(String server)
    {
        this.server = server;
    }

    public ESTServiceBuilder withTlsTrustAnchors(Set<TrustAnchor> tlsTrustAnchors)
    {
        this.tlsTrustAnchors = tlsTrustAnchors;
        return this;
    }

    public ESTServiceBuilder withClientKeystore(KeyStore clientKeystore)
    {
        this.clientKeystore = clientKeystore;
        return this;
    }

    public ESTServiceBuilder withClientKeystorePassword(char[] clientKeystorePassword)
    {
        this.clientKeystorePassword = clientKeystorePassword;
        return this;
    }

    public ESTServiceBuilder withHostNameAuthorizer(TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)
    {
        this.hostNameAuthorizer = hostNameAuthorizer;
        return this;
    }

    public ESTServiceBuilder withTlsAuthorizer(TLSAuthorizer<SSLSession> tlsAuthorizer)
    {
        this.tlsAuthorizer = tlsAuthorizer;
        return this;
    }

    public ESTServiceBuilder withRevocationList(CRL revocationList)
    {
        this.revocationList = revocationList;
        return this;
    }

    public ESTServiceBuilder withClientProvider(ESTHttpClientProvider clientProvider)
    {
        this.clientProvider = clientProvider;
        return this;
    }

    public ESTService build()
    {
        if (clientProvider == null)
        {
            clientProvider = new DefaultESTHttpClientProvider(
                tlsTrustAnchors,
                clientKeystore,
                clientKeystorePassword,
                hostNameAuthorizer, revocationList);
        }

        return new ESTService(
            tlsTrustAnchors,
            clientKeystore,
            clientKeystorePassword,
            hostNameAuthorizer,
            server,
            tlsAuthorizer,
            revocationList,
            clientProvider);
    }

    public static class DefaultESTHttpClientProvider
        implements ESTHttpClientProvider
    {


        private Set<TrustAnchor> tlsTrustAnchors;
        private KeyStore clientKeystore;
        private char[] clientKeystorePassword;
        private TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer;
        private CRL revocationList;

        public DefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors, KeyStore clientKeystore, char[] clientKeystorePassword, TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer, CRL revocationList)
        {
            this.tlsTrustAnchors = tlsTrustAnchors;
            this.clientKeystore = clientKeystore;
            this.clientKeystorePassword = clientKeystorePassword;
            this.hostNameAuthorizer = hostNameAuthorizer;
            this.revocationList = revocationList;
        }

        public ESTHttpClient makeHttpClient(TLSAuthorizer<SSLSession> tlsAuthorizer)
            throws Exception
        {
            TLSAcceptedIssuersSource acceptedIssuersSource = (tlsTrustAnchors != null) ? new TLSAcceptedIssuersSource()
            {
                public Set<TrustAnchor> anchors()
                {
                    return tlsTrustAnchors;
                }
            } : null;

            KeyManagerFactory keyFact = null;
            if (clientKeystore != null)
            {
                keyFact = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyFact.init(clientKeystore, clientKeystorePassword);
            }

            if (tlsAuthorizer == null && acceptedIssuersSource == null)
            {
                return new DefaultESTClient(DefaultESTClientSSLSocketProvider.getUsingDefaultSSLSocketFactory(hostNameAuthorizer));
            }

            if (acceptedIssuersSource != null && tlsAuthorizer == null)
            {
                tlsAuthorizer = DefaultESTClientSSLSocketProvider.getCertPathTLSAuthorizer(revocationList);
            }


            return new DefaultESTClient(
                new DefaultESTClientSSLSocketProvider(acceptedIssuersSource, tlsAuthorizer, keyFact, hostNameAuthorizer));
        }
    }
}



