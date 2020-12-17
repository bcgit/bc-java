package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.tls.SecurityParameters;

interface ProvTlsManager
{
    void checkClientTrusted(X509Certificate[] chain, String authType) throws IOException;

    void checkServerTrusted(X509Certificate[] chain, String authType) throws IOException;

    BCX509Key chooseClientKey(String[] keyTypes, Principal[] issuers);

    BCX509Key chooseServerKey(String keyType, Principal[] issuers);

    boolean getEnableSessionCreation();

    ContextData getContextData();

    String getPeerHost();

    String getPeerHostSNI();

    int getPeerPort();

    void notifyHandshakeComplete(ProvSSLConnection connection);

    void notifyHandshakeSession(ProvSSLSessionContext sslSessionContext, SecurityParameters securityParameters,
        JsseSecurityParameters jsseSecurityParameters, ProvSSLSession resumedSession);

    String selectApplicationProtocol(List<String> protocols);
}
