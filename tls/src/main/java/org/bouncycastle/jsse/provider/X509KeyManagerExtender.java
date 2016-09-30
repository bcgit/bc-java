package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

class X509KeyManagerExtender
    extends X509ExtendedKeyManager
{
    private final X509KeyManager baseMgr;

    X509KeyManagerExtender(X509KeyManager baseMgr)
    {
        this.baseMgr = baseMgr;
    }

    public String[] getClientAliases(String keyType, Principal[] principals)
    {
        return baseMgr.getClientAliases(keyType, principals);
    }

    public String chooseClientAlias(String[] keyTypes, Principal[] principals, Socket socket)
    {
        return baseMgr.chooseClientAlias(keyTypes, principals, socket);
    }

    public String[] getServerAliases(String keyType, Principal[] principals)
    {
        return baseMgr.getServerAliases(keyType, principals);
    }

    public String chooseServerAlias(String keyType, Principal[] principals, Socket socket)
    {
        return baseMgr.chooseServerAlias(keyType, principals, socket);
    }

    public X509Certificate[] getCertificateChain(String alias)
    {
        return baseMgr.getCertificateChain(alias);
    }

    public PrivateKey getPrivateKey(String alias)
    {
        return baseMgr.getPrivateKey(alias);
    }
}
