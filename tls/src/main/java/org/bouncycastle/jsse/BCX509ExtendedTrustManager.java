package org.bouncycastle.jsse;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509TrustManager;

public abstract class BCX509ExtendedTrustManager implements X509TrustManager
{
    public abstract void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException;

    public abstract void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException;

    public abstract void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException;

    public abstract void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException;
}
