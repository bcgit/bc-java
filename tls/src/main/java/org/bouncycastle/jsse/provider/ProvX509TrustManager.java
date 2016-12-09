package org.bouncycastle.jsse.provider;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.X509TrustManager;

class ProvX509TrustManager
    implements X509TrustManager
{
    private final Provider pkixProvider;
    private final KeyStore trustStore;

    public ProvX509TrustManager(Provider pkixProvider, KeyStore trustStore)
    {
        this.pkixProvider = pkixProvider;
        this.trustStore = trustStore;
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType)
        throws CertificateException
    {
        // TODO: need to confirm cert and client identity match
        // TODO: need to make sure authType makes sense.
        validatePath(x509Certificates);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType)
        throws CertificateException
    {

        // TODO: need to confirm cert and server identity match
        // TODO: need to make sure authType makes sense.
        validatePath(x509Certificates);
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        try
        {
            Set<X509Certificate> certs = new HashSet<X509Certificate>(trustStore.size());
            for (Enumeration<String> en = trustStore.aliases(); en.hasMoreElements();)
            {
                String alias = (String)en.nextElement();
                if (trustStore.isCertificateEntry(alias))
                {
                    Certificate cert = trustStore.getCertificate(alias);
                    if (cert instanceof X509Certificate)
                    {
                        certs.add((X509Certificate)cert);
                    }
                }
            }
            return certs.toArray(new X509Certificate[certs.size()]);
        }
        catch (Exception e)
        {
            return new X509Certificate[0];
        }
    }

    protected void validatePath(X509Certificate[] x509Certificates)
        throws CertificateException
    {
        try
        {
            CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(Arrays.asList(x509Certificates)), pkixProvider);

            CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX", pkixProvider);

            X509CertSelector constraints = new X509CertSelector();

            constraints.setCertificate(x509Certificates[0]);

            PKIXBuilderParameters param = new PKIXBuilderParameters(trustStore, constraints);
            param.addCertStore(certStore);
            param.setRevocationEnabled(false);

            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)pathBuilder.build(param);
        }
        catch (GeneralSecurityException e)
        {
            throw new CertificateException("unable to process certificates: " + e.getMessage(), e);
        }
    }
}
