package org.bouncycastle.est.jcajce;


import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.net.ssl.SSLSession;

import org.bouncycastle.est.ESTClientProvider;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.ESTServiceBuilder;
import org.bouncycastle.est.TLSAuthorizer;
import org.bouncycastle.est.TLSHostNameAuthorizer;


/**
 * Build a RFC7030 client.
 */
public class JcaESTServiceBuilder
    extends ESTServiceBuilder
{
    protected Set<TrustAnchor> tlsTrustAnchors;
    protected KeyStore clientKeystore;
    protected char[] clientKeystorePassword;
    protected TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    protected TLSAuthorizer tlsAuthorizer;
    protected CRL revocationList;

    public JcaESTServiceBuilder(String server)
    {
        super(server);
        this.tlsAuthorizer = new TLSAuthorizer()
        {
            public void authorize(
                Set<TrustAnchor> acceptedIssuers,
                X509Certificate[] chain,
                String authType)
                throws CertificateException
            {
                // Does nothing, will accept any and all tendered certificates from the server.
            }
        };
    }

    public JcaESTServiceBuilder(String server, Set<TrustAnchor> tlsTrustAnchors)
    {
        super(server);
        if (tlsTrustAnchors == null || tlsTrustAnchors.isEmpty())
        {
            //
            // You must set trust anchors to use this constructor, if you desire the service to accept
            // any server tendered certificates then use the alternative constructor.
            //
            throw new IllegalStateException("Trust anchors must be not null and not empty.");
        }
        this.tlsTrustAnchors = tlsTrustAnchors;
    }

    public JcaESTServiceBuilder withClientKeystore(KeyStore clientKeystore, char[] clientKeystorePassword)
    {
        this.clientKeystore = clientKeystore;
        this.clientKeystorePassword = clientKeystorePassword;
        return this;
    }

    public JcaESTServiceBuilder withHostNameAuthorizer(TLSHostNameAuthorizer hostNameAuthorizer)
    {
        this.hostNameAuthorizer = hostNameAuthorizer;
        return this;
    }

    public JcaESTServiceBuilder withRevocationList(CRL revocationList)
    {
        this.revocationList = revocationList;
        return this;
    }

    public JcaESTServiceBuilder withClientProvider(ESTClientProvider clientProvider)
    {
        this.clientProvider = clientProvider;
        return this;
    }

    public JcaESTServiceBuilder withTlsTrustAnchors(Set<TrustAnchor> tlsTrustAnchors)
    {
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
                hostNameAuthorizer, revocationList, tlsAuthorizer);
        }

        return super.build();
    }

}



