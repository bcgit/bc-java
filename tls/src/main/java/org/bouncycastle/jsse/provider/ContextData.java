package org.bouncycastle.jsse.provider;

import java.security.SecureRandom;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

final class ContextData
{
    private final X509KeyManager km;
    private final X509TrustManager tm;
    private final SecureRandom sr;

    ContextData(X509KeyManager km, X509TrustManager tm, SecureRandom sr)
    {
        this.km = km;
        this.tm = tm;
        this.sr = sr;
    }

    X509KeyManager getKeyManager()
    {
        return km;
    }

    X509TrustManager getTrustManager()
    {
        return tm;
    }

    SecureRandom getSecureRandom()
    {
        return sr;
    }
}
