package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jsse.BCX509ExtendedTrustManager;

class ImportX509TrustManager_7
    extends BCX509ExtendedTrustManager
    implements ImportX509TrustManager
{
    final X509ExtendedTrustManager x509TrustManager;

    ImportX509TrustManager_7(X509ExtendedTrustManager x509TrustManager)
    {
        this.x509TrustManager = x509TrustManager;
    }

    public X509TrustManager unwrap()
    {
        return x509TrustManager;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(chain, authType);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(chain, authType, socket);
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException
    {
        x509TrustManager.checkClientTrusted(chain, authType, engine);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(chain, authType);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(chain, authType, socket);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException
    {
        x509TrustManager.checkServerTrusted(chain, authType, engine);
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        return x509TrustManager.getAcceptedIssuers();
    }
}
