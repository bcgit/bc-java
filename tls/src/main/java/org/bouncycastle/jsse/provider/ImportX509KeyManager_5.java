package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509Key;

final class ImportX509KeyManager_5
    extends BCX509ExtendedKeyManager
    implements ImportX509KeyManager
{
    final X509ExtendedKeyManager x509KeyManager;

    ImportX509KeyManager_5(X509ExtendedKeyManager x509KeyManager)
    {
        this.x509KeyManager = x509KeyManager;
    }

    public X509KeyManager unwrap()
    {
        return x509KeyManager;
    }

    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket)
    {
        return x509KeyManager.chooseClientAlias(keyType, issuers, socket);
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine)
    {
        return x509KeyManager.chooseEngineClientAlias(keyType, issuers, engine);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine)
    {
        return x509KeyManager.chooseEngineServerAlias(keyType, issuers, engine);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        return x509KeyManager.chooseServerAlias(keyType, issuers, socket);
    }

    public X509Certificate[] getCertificateChain(String alias)
    {
        return x509KeyManager.getCertificateChain(alias);
    }

    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        return x509KeyManager.getClientAliases(keyType, issuers);
    }

    public PrivateKey getPrivateKey(String alias)
    {
        return x509KeyManager.getPrivateKey(alias);
    }

    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        return x509KeyManager.getServerAliases(keyType, issuers);
    }

    @Override
    protected BCX509Key getKeyBC(String keyType, String alias)
    {
        return ProvX509Key.from(x509KeyManager, keyType, alias);
    }

    @Override
    protected BCX509Key validateKeyBC(boolean forServer, String keyType, String alias, Socket socket)
    {
        return ProvX509Key.validate(x509KeyManager, forServer, keyType, alias, TransportData.from(socket));
    }

    @Override
    protected BCX509Key validateKeyBC(boolean forServer, String keyType, String alias, SSLEngine engine)
    {
        return ProvX509Key.validate(x509KeyManager, forServer, keyType, alias, TransportData.from(engine));
    }
}
