package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;

interface ProvTlsManager
{
    void checkClientTrusted(X509Certificate[] chain, String authType) throws IOException;

    void checkServerTrusted(X509Certificate[] chain, String authType) throws IOException;

    ProvX509Key chooseClientKey(String[] keyTypes, Principal[] issuers);

    ProvX509Key chooseServerKey(String keyType, Principal[] issuers);

    boolean getEnableSessionCreation();

    ContextData getContextData();

    String getPeerHost();

    String getPeerHostSNI();

    int getPeerPort();

    void notifyHandshakeComplete(ProvSSLConnection connection);

    void notifyHandshakeSession(ProvSSLSessionHandshake handshakeSession);

    String selectApplicationProtocol(List<String> protocols);
}
