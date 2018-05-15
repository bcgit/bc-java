package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

class ProvX509ExtendedTrustManager_7
    extends X509ExtendedTrustManager
{
    private final ProvX509TrustManager trustManager;

    public ProvX509ExtendedTrustManager_7(ProvX509TrustManager trustManager)
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
        trustManager.checkClientTrusted(x509Certificates, authType, socket);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType, Socket socket)
        throws CertificateException
    {
        trustManager.checkServerTrusted(x509Certificates, authType, socket);
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType, SSLEngine sslEngine)
        throws CertificateException
    {
        trustManager.checkClientTrusted(x509Certificates, authType, sslEngine);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType, SSLEngine sslEngine)
        throws CertificateException
    {
        trustManager.checkServerTrusted(x509Certificates, authType, sslEngine);
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        return trustManager.getAcceptedIssuers();
    }
}
