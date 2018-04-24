package org.bouncycastle.jsse.provider;

import java.security.cert.X509Certificate;

interface ProvTlsManager
{
    ProvSSLContextSpi getContext();

    boolean getEnableSessionCreation();

    ProvSSLParameters getProvSSLParameters();

    ContextData getContextData();

    String getPeerHost();

    int getPeerPort();

    boolean isClientTrusted(X509Certificate[] chain, String authType);

    boolean isServerTrusted(X509Certificate[] chain, String authType);

    void notifyHandshakeComplete(ProvSSLConnection connection); 
}
