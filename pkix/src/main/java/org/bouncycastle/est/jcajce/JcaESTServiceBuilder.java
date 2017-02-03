package org.bouncycastle.est.jcajce;


import org.bouncycastle.est.ESTHttpClientProvider;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.ESTServiceBuilder;
import org.bouncycastle.est.http.TLSAuthorizer;
import org.bouncycastle.est.http.TLSHostNameAuthorizer;

import javax.net.ssl.SSLSession;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.TrustAnchor;
import java.util.Set;


/**
 * Build a RFC7030 client.
 */
public class JcaESTServiceBuilder extends ESTServiceBuilder
{
    protected Set<TrustAnchor> tlsTrustAnchors;
    protected KeyStore clientKeystore;
    protected char[] clientKeystorePassword;
    protected TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    protected TLSAuthorizer<SSLSession> tlsAuthorizer;
    protected CRL revocationList;

    public JcaESTServiceBuilder(String server)
    {
        super(server);
    }

    public JcaESTServiceBuilder(String server, Set<TrustAnchor> tlsTrustAnchors) {
        super(server);
        this.tlsTrustAnchors = tlsTrustAnchors;
    }

    public JcaESTServiceBuilder withClientKeystore(KeyStore clientKeystore, char[] clientKeystorePassword)
    {
        this.clientKeystore = clientKeystore;
        this.clientKeystorePassword = clientKeystorePassword;
        return this;
    }

    public JcaESTServiceBuilder withHostNameAuthorizer(TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)
    {
        this.hostNameAuthorizer = hostNameAuthorizer;
        return this;
    }

    public JcaESTServiceBuilder withTlsAuthorizer(TLSAuthorizer<SSLSession> tlsAuthorizer)
    {
        this.tlsAuthorizer = tlsAuthorizer;
        return this;
    }

    public JcaESTServiceBuilder withRevocationList(CRL revocationList)
    {
        this.revocationList = revocationList;
        return this;
    }

    public JcaESTServiceBuilder withClientProvider(ESTHttpClientProvider clientProvider)
    {
        this.clientProvider = clientProvider;
        return this;
    }

    public JcaESTServiceBuilder withTlsTrustAnchors(Set<TrustAnchor> tlsTrustAnchors) {
        this.tlsTrustAnchors = tlsTrustAnchors;
        return this;
    }

    public ESTService build()
    {
        if (clientProvider == null)
        {
            clientProvider = new JcaDefaultESTHttpClientProvider(
                tlsTrustAnchors,
                clientKeystore,
                clientKeystorePassword,
                hostNameAuthorizer, revocationList);
        }

        return super.build();
    }

}



