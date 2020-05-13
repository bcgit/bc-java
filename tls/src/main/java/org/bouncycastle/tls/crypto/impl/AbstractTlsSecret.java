package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/**
 * Base class for a TlsSecret implementation which captures common code and fields.
 */
public abstract class AbstractTlsSecret
    implements TlsSecret
{
    protected byte[] data;

    /**
     * Base constructor.
     *
     * @param data the byte[] making up the secret value.
     */
    protected AbstractTlsSecret(byte[] data)
    {
        this.data = data;
    }

    protected void checkAlive()
    {
        if (data == null)
        {
            throw new IllegalStateException("Secret has already been extracted or destroyed");
        }
    }

    protected abstract AbstractTlsCrypto getCrypto();

    public synchronized void destroy()
    {
        if (data != null)
        {
            // TODO Is there a way to ensure the data is really overwritten?
            Arrays.fill(data, (byte)0);
            this.data = null;
        }
    }

    public synchronized byte[] encrypt(TlsCertificate certificate) throws IOException
    {
        checkAlive();

        return getCrypto().createEncryptor(certificate).encrypt(data, 0, data.length);
    }

    public synchronized byte[] extract()
    {
        checkAlive();

        byte[] result = data;
        this.data = null;
        return result;
    }

    public synchronized boolean isAlive()
    {
        return null != data;
    }

    synchronized byte[] copyData()
    {
        return Arrays.clone(data);
    }
}
