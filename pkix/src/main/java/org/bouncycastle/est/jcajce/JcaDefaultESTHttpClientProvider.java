package org.bouncycastle.est.jcajce;

import org.bouncycastle.est.*;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSession;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.TrustAnchor;
import java.util.Set;

public class JcaDefaultESTHttpClientProvider
        implements ESTClientProvider
{


    private final Set<TrustAnchor> tlsTrustAnchors;
    private final KeyStore clientKeystore;
    private final char[] clientKeystorePassword;
    private final TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    private final CRL revocationList;
    private final TLSAuthorizer tlsAuthorizer;

    public JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors,
                                           KeyStore clientKeystore,
                                           char[] clientKeystorePassword,
                                           TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer,
                                           CRL revocationList, TLSAuthorizer tlsAuthorizer) {
        this.tlsTrustAnchors = tlsTrustAnchors;
        this.clientKeystore = clientKeystore;
        this.clientKeystorePassword = clientKeystorePassword;
        this.hostNameAuthorizer = hostNameAuthorizer;
        this.revocationList = revocationList;
        this.tlsAuthorizer = tlsAuthorizer;
    }

    public ESTClient makeClient()
            throws Exception {
        TLSAcceptedIssuersSource acceptedIssuersSource = (tlsTrustAnchors != null) ? new TLSAcceptedIssuersSource() {
            public Set<TrustAnchor> anchors() {
                return tlsTrustAnchors;
            }
        } : null;

        KeyManagerFactory keyFact = null;
        if (clientKeystore != null) {
            keyFact = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyFact.init(clientKeystore, clientKeystorePassword);
        }

        TLSAuthorizer tlsAuthorizer = this.tlsAuthorizer;

        if (tlsAuthorizer == null && acceptedIssuersSource == null) {
            return new DefaultESTClient(DefaultESTClientSourceProvider.getUsingDefaultSSLSocketFactory(hostNameAuthorizer));
        }

        if (acceptedIssuersSource != null && tlsAuthorizer == null) {
            tlsAuthorizer = DefaultESTClientSourceProvider.getCertPathTLSAuthorizer(revocationList);
        }

        return new DefaultESTClient(
                new DefaultESTClientSourceProvider(acceptedIssuersSource, tlsAuthorizer, keyFact, hostNameAuthorizer));
    }

    public boolean isTrusted() {
        return tlsTrustAnchors != null && !tlsTrustAnchors.isEmpty();
    }
}
