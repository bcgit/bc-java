package org.bouncycastle.jsse.provider;

import java.security.cert.X509Certificate;

interface ProvTlsManager
{
    ProvSSLContextSpi getContext();

    ProvSSLParameters getProvSSLParameters();

    ContextData getContextData();

    String getPeerHost();

    boolean isClientTrusted(X509Certificate[] chain, String authType);

    boolean isServerTrusted(X509Certificate[] chain, String authType);

    void notifyHandshakeComplete(ProvSSLConnection connection); 
}
