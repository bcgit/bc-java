package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateException;
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
        System.err.println("Client");
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType)
        throws CertificateException
    {

        System.err.println("Server");

        System.err.println(Arrays.asList(x509Certificates));
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        try
        {
            List<X509Certificate> certs = new ArrayList<X509Certificate>(trustStore.size());

            for (Enumeration en = trustStore.aliases(); en.hasMoreElements();)
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

    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket)
        throws CertificateException
    {
        System.err.println("Client1");
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket)
        throws CertificateException
    {
        System.err.println("Server1");
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine)
        throws CertificateException
    {
        System.err.println("Client2");
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine)
        throws CertificateException
    {
        System.err.println("Server2");
    }
}
