package org.bouncycastle.jsse.provider;

import java.security.cert.X509Certificate;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

interface ProvTlsManager
{
    ProvSSLContextSpi getContext();

    ContextData getContextData();

    SSLParameters getSSLParameters();

    boolean isClientTrusted(X509Certificate[] chain, String authType);

    boolean isServerTrusted(X509Certificate[] chain, String authType);

    void notifyHandshakeComplete(SSLSession session); 
}
