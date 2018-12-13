package org.bouncycastle.jsse.provider;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

class ExportX509TrustManager_5
    implements X509TrustManager
{
    final ProvX509TrustManager x509TrustManager;

    ExportX509TrustManager_5(ProvX509TrustManager x509TrustManager)
    {
        this.x509TrustManager = x509TrustManager;
    }

    ProvX509TrustManager unwrap()
    {
        return x509TrustManager;
    }

    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(x509Certificates, authType);
    }

    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(x509Certificates, authType);
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        return x509TrustManager.getAcceptedIssuers();
    }
}
