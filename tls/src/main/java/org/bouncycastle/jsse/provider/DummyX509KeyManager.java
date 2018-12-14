package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509ExtendedKeyManager;

final class DummyX509KeyManager
    extends X509ExtendedKeyManager
{
    static final X509ExtendedKeyManager INSTANCE = new DummyX509KeyManager();

    private DummyX509KeyManager()
    {
    }

    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket)
    {
        return null;
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        return null;
    }

    public X509Certificate[] getCertificateChain(String alias)
    {
        return null;
    }

    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        return null;
    }

    public PrivateKey getPrivateKey(String alias)
    {
        return null;
    }

    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        return null;
    }
}
