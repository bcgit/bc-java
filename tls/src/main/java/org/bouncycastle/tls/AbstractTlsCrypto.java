package org.bouncycastle.tls;

import java.security.SecureRandom;

public abstract class AbstractTlsCrypto implements TlsCrypto
{
    protected final SecureRandom entropySource;
    protected TlsContext context;

    protected AbstractTlsCrypto(SecureRandom entropySource)
    {
        this.entropySource = entropySource;
    }

    void init(TlsContext context)
    {
        this.context = context;
    }

    public SecureRandom getSecureRandom()
    {
        return entropySource;
    }
}
