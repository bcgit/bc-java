package org.bouncycastle.est.jcajce;

import org.bouncycastle.est.*;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSession;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.TrustAnchor;
import java.util.Set;

public class JcaDefaultESTHttpClientProvider
        implements ESTClientProvider<SSLSession>
{


    private final Set<TrustAnchor> tlsTrustAnchors;
    private final KeyStore clientKeystore;
    private final char[] clientKeystorePassword;
    private final TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    private final CRL revocationList;
    private final TLSAuthorizer<SSLSession> tlsAuthorizer;

    public JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors,
                                           KeyStore clientKeystore,
                                           char[] clientKeystorePassword,
                                           TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer,
                                           CRL revocationList, TLSAuthorizer<SSLSession> tlsAuthorizer) {
        this.tlsTrustAnchors = tlsTrustAnchors;
        this.clientKeystore = clientKeystore;
        this.clientKeystorePassword = clientKeystorePassword;
        this.hostNameAuthorizer = hostNameAuthorizer;
        this.revocationList = revocationList;
        this.tlsAuthorizer = tlsAuthorizer;
    }

    public ESTClient makeHttpClient()
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

        TLSAuthorizer<SSLSession> tlsAuthorizer = this.tlsAuthorizer;

        if (tlsAuthorizer == null && acceptedIssuersSource == null) {
            return new DefaultESTClient(DefaultESTClientSSLSocketProvider.getUsingDefaultSSLSocketFactory(hostNameAuthorizer));
        }

        if (acceptedIssuersSource != null && tlsAuthorizer == null) {
            tlsAuthorizer = DefaultESTClientSSLSocketProvider.getCertPathTLSAuthorizer(revocationList);
        }

        return new DefaultESTClient(
                new DefaultESTClientSSLSocketProvider(acceptedIssuersSource, tlsAuthorizer, keyFact, hostNameAuthorizer));
    }

    public boolean isTrusted() {
        return tlsTrustAnchors != null && !tlsTrustAnchors.isEmpty();
    }
}
