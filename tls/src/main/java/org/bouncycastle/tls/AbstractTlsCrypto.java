package org.bouncycastle.tls;

import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.TlsCrypto;

/**
 * Base implementation of TlsCrypto which carries the context as well.
 */
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
