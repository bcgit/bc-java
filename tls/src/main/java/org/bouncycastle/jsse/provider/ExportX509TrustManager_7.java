package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

import org.bouncycastle.jsse.BCX509ExtendedTrustManager;

class ExportX509TrustManager_7
    extends X509ExtendedTrustManager
    implements ExportX509TrustManager
{
    final BCX509ExtendedTrustManager x509TrustManager;

    ExportX509TrustManager_7(BCX509ExtendedTrustManager x509TrustManager)
    {
        this.x509TrustManager = x509TrustManager;
    }

    public BCX509ExtendedTrustManager unwrap()
    {
        return x509TrustManager;
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(x509Certificates, authType);
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType, Socket socket)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(x509Certificates, authType, socket);
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType, SSLEngine engine)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(x509Certificates, authType, engine);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(x509Certificates, authType);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType, Socket socket)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(x509Certificates, authType, socket);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType, SSLEngine engine)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(x509Certificates, authType, engine);
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        return x509TrustManager.getAcceptedIssuers();
    }
}
