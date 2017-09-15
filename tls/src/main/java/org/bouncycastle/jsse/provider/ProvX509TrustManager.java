package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509TrustManager;

interface ProvX509TrustManager
    extends X509TrustManager
{
    void checkClientTrusted(X509Certificate[] x509Certificates, String authType, Socket socket)
        throws CertificateException;

    void checkServerTrusted(X509Certificate[] x509Certificates, String authType, Socket socket)
        throws CertificateException;

    void checkClientTrusted(X509Certificate[] x509Certificates, String authType, SSLEngine sslEngine)
        throws CertificateException;

    void checkServerTrusted(X509Certificate[] x509Certificates, String authType, SSLEngine sslEngine)
        throws CertificateException;
}
