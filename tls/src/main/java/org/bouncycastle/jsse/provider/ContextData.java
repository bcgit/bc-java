package org.bouncycastle.jsse.provider;

import javax.net.ssl.X509ExtendedKeyManager;

import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.tls.crypto.TlsCrypto;

final class ContextData
{
    private final ProvSSLContextSpi context;
    private final TlsCrypto crypto;
    private final X509ExtendedKeyManager x509KeyManager;
    private final BCX509ExtendedTrustManager x509TrustManager;
    private final ProvSSLSessionContext clientSessionContext;
    private final ProvSSLSessionContext serverSessionContext;

    ContextData(ProvSSLContextSpi context, TlsCrypto crypto, X509ExtendedKeyManager x509KeyManager,
        BCX509ExtendedTrustManager x509TrustManager)
    {
        this.context = context;
        this.crypto = crypto;
        this.x509KeyManager = x509KeyManager;
        this.x509TrustManager = x509TrustManager;
        this.clientSessionContext = new ProvSSLSessionContext(this);
        this.serverSessionContext = new ProvSSLSessionContext(this);
    }

    ProvSSLContextSpi getContext()
    {
        return context;
    }

    TlsCrypto getCrypto()
    {
        return crypto;
    }

    ProvSSLSessionContext getClientSessionContext()
    {
        return clientSessionContext;
    }

    ProvSSLSessionContext getServerSessionContext()
    {
        return serverSessionContext;
    }

    X509ExtendedKeyManager getX509KeyManager()
    {
        return x509KeyManager;
    }

    BCX509ExtendedTrustManager getX509TrustManager()
    {
        return x509TrustManager;
    }
}
