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
                    BCX509Key key = validateKeyBC(false, keyType, alias, socket);
                    if (null != key)
                    {
                        return key;
                    }
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
                    BCX509Key key = validateKeyBC(false, keyType, alias, engine);
                    if (null != key)
                    {
                        return key;
                    }
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
                    BCX509Key key = validateKeyBC(true, keyType, alias, engine);
                    if (null != key)
                    {
                        return key;
                    }
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
                    BCX509Key key = validateKeyBC(true, keyType, alias, socket);
                    if (null != key)
                    {
                        return key;
                    }
                }
            }
        }
        return null;
    }

    protected abstract BCX509Key getKeyBC(String keyType, String alias);

    protected BCX509Key validateKeyBC(boolean forServer, String keyType, String alias, Socket socket)
    {
        return getKeyBC(keyType, alias);
    }

    protected BCX509Key validateKeyBC(boolean forServer, String keyType, String alias, SSLEngine engine)
    {
        return getKeyBC(keyType, alias);
    }
}
