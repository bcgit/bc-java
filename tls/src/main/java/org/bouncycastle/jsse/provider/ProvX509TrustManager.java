package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

class ProvX509TrustManager
    extends X509ExtendedTrustManager
{
    private final KeyStore trustStore;

    public ProvX509TrustManager(KeyStore trustStore)
    {
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

    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType, Socket socket)
        throws CertificateException
    {
        // TODO: need to confirm cert and client identity match
        // TODO: need to make sure authType makes sense.
        validatePath(x509Certificates);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType, Socket socket)
        throws CertificateException
    {
        // TODO: need to confirm cert and server identity match
        // TODO: need to make sure authType makes sense.
        validatePath(x509Certificates);
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType, SSLEngine sslEngine)
        throws CertificateException
    {
        // TODO: need to confirm cert and client identity match
        // TODO: need to make sure authType makes sense.
        validatePath(x509Certificates);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType, SSLEngine sslEngine)
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
            List<X509Certificate> certs = new ArrayList<X509Certificate>(trustStore.size());

            for (Enumeration<String> en = trustStore.aliases(); en.hasMoreElements();)
            {
                String alias = (String)en.nextElement();

                if (trustStore.isCertificateEntry(alias))
                {
                    java.security.cert.Certificate cert = trustStore.getCertificate(alias);

                    if (cert instanceof X509Certificate)
                    {
                        certs.add((X509Certificate)cert);
                    }
                }
                else if (trustStore.isKeyEntry(alias))
                {
                    java.security.cert.Certificate[] certChain = trustStore.getCertificateChain(alias);

                    if (certChain != null && certChain.length > 0)
                    {
                        if (certChain[0] instanceof X509Certificate)
                        {
                            certs.add((X509Certificate)certChain[0]);
                        }
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

    private void validatePath(X509Certificate[] x509Certificates)
        throws CertificateException
    {
        new Exception().printStackTrace(System.err);
        try
        {
            CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(x509Certificates)), "BC");

            CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX", "BC");

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
