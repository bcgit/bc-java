package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509Key;

final class DummyX509KeyManager
    extends BCX509ExtendedKeyManager
{
    static final BCX509ExtendedKeyManager INSTANCE = new DummyX509KeyManager();

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

    @Override
    public BCX509Key getKeyBC(String alias)
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
