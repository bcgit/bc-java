package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/**
 * Base class for a TlsSecret implementation which captures common code and fields.
 */
public abstract class AbstractTlsSecret
    implements TlsSecret
{
    protected static final int MD5_SIZE = 16;

    // SSL3 magic mix constants ("A", "BB", "CCC", ...)
    protected static final byte[][] SSL3_CONST = generateSSL3Constants();

    private static byte[][] generateSSL3Constants()
    {
        int n = 10;
        byte[][] arr = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            byte[] b = new byte[i + 1];
            Arrays.fill(b, (byte)('A' + i));
            arr[i] = b;
        }
        return arr;
    }

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

    public synchronized byte[] encrypt(TlsCertificate certificate) throws IOException
    {
        checkAlive();

        return getCrypto().createEncryptor(certificate).encrypt(data, 0, data.length);
    }

    public synchronized void destroy()
    {
        if (data != null)
        {
            // TODO Is there a way to ensure the data is really overwritten?
            Arrays.fill(data, (byte)0);
            this.data = null;
        }
    }

    public synchronized byte[] extract()
    {
        checkAlive();

        byte[] result = data;
        this.data = null;
        return result;
    }

    public TlsCipher createCipher(TlsCryptoParameters contextParams, int encryptionAlgorithm, int macAlgorithm)
        throws IOException
    {
        return getCrypto().createCipher(contextParams, encryptionAlgorithm, macAlgorithm);
    }

    byte[] copyData()
    {
        return Arrays.clone(data);
    }

    protected void checkAlive()
    {
        if (data == null)
        {
            throw new IllegalStateException("Secret has already been extracted or destroyed");
        }
    }

    protected abstract AbstractTlsCrypto getCrypto();
}
