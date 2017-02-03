package org.bouncycastle.est.jcajce;

import org.bouncycastle.est.ESTHttpClientProvider;
import org.bouncycastle.est.http.*;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSession;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.TrustAnchor;
import java.util.Set;

public class JcaDefaultESTHttpClientProvider
        implements ESTHttpClientProvider<SSLSession> {


    private Set<TrustAnchor> tlsTrustAnchors;
    private KeyStore clientKeystore;
    private char[] clientKeystorePassword;
    private TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer;
    private CRL revocationList;

    public JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors,
                                           KeyStore clientKeystore,
                                           char[] clientKeystorePassword,
                                           TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer,
                                           CRL revocationList) {
        this.tlsTrustAnchors = tlsTrustAnchors;
        this.clientKeystore = clientKeystore;
        this.clientKeystorePassword = clientKeystorePassword;
        this.hostNameAuthorizer = hostNameAuthorizer;
        this.revocationList = revocationList;
    }

    public ESTHttpClient makeHttpClient(TLSAuthorizer<SSLSession> tlsAuthorizer)
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
