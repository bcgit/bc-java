package org.bouncycastle.est;


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

    protected TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    final protected String server;
    protected TLSAuthorizer<SSLSession> tlsAuthorizer;
    protected ESTHttpClientProvider clientProvider;

    public ESTServiceBuilder(String server)
    {
        this.server = server;
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


    public ESTServiceBuilder withClientProvider(ESTHttpClientProvider clientProvider)
    {
        this.clientProvider = clientProvider;
        return this;
    }

    public ESTService build()
    {
//        if (clientProvider == null)
//        {
//            clientProvider = new JcaDefaultESTHttpClientProvider(
//                tlsTrustAnchors,
//                clientKeystore,
//                clientKeystorePassword,
//                hostNameAuthorizer, revocationList);
//        }

        return new ESTService(
            hostNameAuthorizer,
            server,
            tlsAuthorizer,
            clientProvider);
    }

}



