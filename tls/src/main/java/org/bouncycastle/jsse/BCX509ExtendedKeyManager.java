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
        if (null != keyTypes)
        {
            for (String keyType : keyTypes)
            {
                String alias = chooseClientAlias(new String[]{ keyType }, issuers, socket);
                if (null != alias)
                {
                    return getKeyBC(keyType, alias);
                }
            }
        }
        return null;
    }

    public BCX509Key chooseEngineClientKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine)
    {
        if (null != keyTypes)
        {
            for (String keyType : keyTypes)
            {
                String alias = chooseEngineClientAlias(new String[]{ keyType }, issuers, engine);
                if (null != alias)
                {
                    return getKeyBC(keyType, alias);
                }
            }
        }
        return null;
    }

    public BCX509Key chooseEngineServerKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine)
    {
        if (null != keyTypes)
        {
            for (String keyType : keyTypes)
            {
                String alias = chooseEngineServerAlias(keyType, issuers, engine);
                if (null != alias)
                {
                    return getKeyBC(keyType, alias);
                }
            }
        }
        return null;
    }

    public BCX509Key chooseServerKeyBC(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        if (null != keyTypes)
        {
            for (String keyType : keyTypes)
            {
                String alias = chooseServerAlias(keyType, issuers, socket);
                if (null != alias)
                {
                    return getKeyBC(keyType, alias);
                }
            }
        }
        return null;
    }

    protected abstract BCX509Key getKeyBC(String keyType, String alias);
}
