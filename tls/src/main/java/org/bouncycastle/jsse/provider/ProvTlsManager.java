package org.bouncycastle.jsse.provider;

import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSession;

interface ProvTlsManager
{
    ProvSSLContextSpi getContext();

    ProvSSLParameters getProvSSLParameters();

    ContextData getContextData();

    boolean isClientTrusted(X509Certificate[] chain, String authType);

    boolean isServerTrusted(X509Certificate[] chain, String authType);

    void notifyHandshakeComplete(SSLSession session); 
}
