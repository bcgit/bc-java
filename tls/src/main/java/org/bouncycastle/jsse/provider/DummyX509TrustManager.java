package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;

import org.bouncycastle.jsse.BCX509ExtendedTrustManager;

final class DummyX509TrustManager
    extends BCX509ExtendedTrustManager
{
    static final BCX509ExtendedTrustManager INSTANCE = new DummyX509TrustManager();

    private DummyX509TrustManager()
    {
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException
    {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException
    {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException
    {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
    {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException
    {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException
    {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        return new X509Certificate[0];
    }
}
