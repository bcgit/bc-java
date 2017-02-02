package org.bouncycastle.est;

import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.TrustAnchor;
import java.util.Set;

import javax.net.ssl.SSLSession;

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


    public ESTService build()
    {
        return new ESTService(
            tlsTrustAnchors,
            clientKeystore,
            clientKeystorePassword,
            hostNameAuthorizer,
            server,
            tlsAuthorizer,
            revocationList);
    }

}
