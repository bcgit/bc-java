package org.bouncycastle.jsse;

import java.net.Socket;
import java.security.Principal;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

public abstract class BCX509ExtendedKeyManager
    extends X509ExtendedKeyManager
{
    public BCX509Key chooseClientKeyBC(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        return getKeyBC(chooseClientAlias(keyTypes, issuers, socket));
    }

    public BCX509Key chooseEngineClientKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine)
    {
        return getKeyBC(chooseEngineClientAlias(keyTypes, issuers, engine));
    }

    public BCX509Key chooseEngineServerKeyBC(String keyType, Principal[] issuers, SSLEngine engine)
    {
        return getKeyBC(chooseEngineServerAlias(keyType, issuers, engine));
    }

    public BCX509Key chooseServerKeyBC(String keyType, Principal[] issuers, Socket socket)
    {
        return getKeyBC(chooseServerAlias(keyType, issuers, socket));
    }

    public abstract BCX509Key getKeyBC(String alias);
}
