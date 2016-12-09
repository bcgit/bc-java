package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

class ProvX509ExtendedTrustManager
    extends X509ExtendedTrustManager
{
    private final ProvX509TrustManager trustManager;

    public ProvX509ExtendedTrustManager(ProvX509TrustManager trustManager)
    {
        this.trustManager = trustManager;
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType)
        throws CertificateException
    {
        trustManager.checkClientTrusted(x509Certificates, authType);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType)
        throws CertificateException
    {
        trustManager.checkServerTrusted(x509Certificates, authType);
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType, Socket socket)
        throws CertificateException
    {
        // TODO: need to confirm cert and client identity match
        // TODO: need to make sure authType makes sense.
        trustManager.validatePath(x509Certificates);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType, Socket socket)
        throws CertificateException
    {
        // TODO: need to confirm cert and server identity match
        // TODO: need to make sure authType makes sense.
        trustManager.validatePath(x509Certificates);
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType, SSLEngine sslEngine)
        throws CertificateException
    {
        // TODO: need to confirm cert and client identity match
        // TODO: need to make sure authType makes sense.
        trustManager.validatePath(x509Certificates);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType, SSLEngine sslEngine)
        throws CertificateException
    {
        // TODO: need to confirm cert and server identity match
        // TODO: need to make sure authType makes sense.
        trustManager.validatePath(x509Certificates);
    }


    public X509Certificate[] getAcceptedIssuers()
    {
        return trustManager.getAcceptedIssuers();
    }
}
