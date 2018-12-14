package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

/*
 * Note that chooseEngineClientAlias() and chooseEngineServerAlias() are inherited (they return
 * null), for compatibility with SunJSSE provider.
 */
final class ImportX509KeyManager_5
    extends X509ExtendedKeyManager
{
    final X509KeyManager x509KeyManager;

    ImportX509KeyManager_5(X509KeyManager x509KeyManager)
    {
        this.x509KeyManager = x509KeyManager;
    }

    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket)
    {
        return x509KeyManager.chooseClientAlias(keyType, issuers, socket);
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
        return x509KeyManager.getClientAliases(keyType, issuers);
    }
}
