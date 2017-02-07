package org.bouncycastle.est.jcajce;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.TrustAnchor;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSession;

import org.bouncycastle.est.ESTClient;
import org.bouncycastle.est.ESTClientProvider;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.est.TLSAcceptedIssuersSource;
import org.bouncycastle.est.ESTAuthorizer;
import org.bouncycastle.est.TLSHostNameAuthorizer;

public class JcaDefaultESTHttpClientProvider
    implements ESTClientProvider
{


    private final Set<TrustAnchor> tlsTrustAnchors;
    private final KeyStore clientKeystore;
    private final char[] clientKeystorePassword;
    private final TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    private final CRL revocationList;
    private final ESTAuthorizer ESTAuthorizer;

    public JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors,
                                           KeyStore clientKeystore,
                                           char[] clientKeystorePassword,
                                           TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer,
                                           CRL revocationList, ESTAuthorizer ESTAuthorizer)
    {
        this.tlsTrustAnchors = tlsTrustAnchors;
        this.clientKeystore = clientKeystore;
        this.clientKeystorePassword = clientKeystorePassword;
        this.hostNameAuthorizer = hostNameAuthorizer;
        this.revocationList = revocationList;
        this.ESTAuthorizer = ESTAuthorizer;
    }

    public ESTClient makeClient()
        throws ESTException
    {
        TLSAcceptedIssuersSource acceptedIssuersSource = (tlsTrustAnchors != null) ? new TLSAcceptedIssuersSource()
        {
            public Set<TrustAnchor> anchors()
            {
                return tlsTrustAnchors;
            }
        } : null;

        try
        {
            KeyManagerFactory keyFact = null;
            if (clientKeystore != null)
            {
                keyFact = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyFact.init(clientKeystore, clientKeystorePassword);
            }

            ESTAuthorizer ESTAuthorizer = this.ESTAuthorizer;

            if (ESTAuthorizer == null && acceptedIssuersSource == null)
            {
                return new DefaultESTClient(DefaultESTClientSourceProvider.getUsingDefaultSSLSocketFactory(hostNameAuthorizer));
            }

            if (acceptedIssuersSource != null && ESTAuthorizer == null)
            {
                ESTAuthorizer = DefaultESTClientSourceProvider.getCertPathTLSAuthorizer(revocationList);
            }

            return new DefaultESTClient(
                new DefaultESTClientSourceProvider(acceptedIssuersSource, ESTAuthorizer, keyFact, hostNameAuthorizer));
        }
        catch (GeneralSecurityException e)
        {
            throw new ESTException(e.getMessage(), e.getCause());
        }
    }

    public boolean isTrusted()
    {
        return tlsTrustAnchors != null && !tlsTrustAnchors.isEmpty();
    }
}
