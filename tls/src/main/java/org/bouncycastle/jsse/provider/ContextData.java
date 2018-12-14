package org.bouncycastle.jsse.provider;

import javax.net.ssl.X509KeyManager;

import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.tls.crypto.TlsCrypto;

final class ContextData
{
    private final TlsCrypto crypto;
    private final X509KeyManager km;
    private final BCX509ExtendedTrustManager tm;
    private final ProvSSLSessionContext clientSessionContext;
    private final ProvSSLSessionContext serverSessionContext;

    ContextData(TlsCrypto crypto, X509KeyManager km, BCX509ExtendedTrustManager tm, ProvSSLSessionContext clientSessionContext,
        ProvSSLSessionContext serverSessionContext)
    {
        this.crypto = crypto;
        this.km = km;
        this.tm = tm;
        this.clientSessionContext = clientSessionContext;
        this.serverSessionContext = serverSessionContext;
    }

    ProvSSLSessionContext getClientSessionContext()
    {
        return clientSessionContext;
    }
    
    TlsCrypto getCrypto()
    {
        return crypto;
    }

    X509KeyManager getKeyManager()
    {
        return km;
    }

    ProvSSLSessionContext getServerSessionContext()
    {
        return serverSessionContext;
    }

    BCX509ExtendedTrustManager getTrustManager()
    {
        return tm;
    }
}
