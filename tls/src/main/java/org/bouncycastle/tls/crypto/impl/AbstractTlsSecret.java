package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsHMAC;
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

    protected abstract TlsSecret adoptLocalSecret(byte[] data);

    protected void checkAlive()
    {
        if (data == null)
        {
            throw new IllegalStateException("Secret has already been extracted or destroyed");
        }
    }

    protected abstract AbstractTlsCrypto getCrypto();

    public TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm)
        throws IOException
    {
        return getCrypto().createCipher(cryptoParams, encryptionAlgorithm, macAlgorithm);
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

    public synchronized TlsSecret hkdfExpand(short hashAlgorithm, byte[] info, int length)
    {
        checkAlive();

        byte[] prk = data;

        TlsCrypto crypto = getCrypto();
        TlsHMAC hmac = crypto.createHMAC(hashAlgorithm);

        hmac.setKey(prk, 0, prk.length);

        byte[] okm = new byte[length];

        int hashLen = hmac.getMacLength();
        byte[] t = new byte[hashLen];
        byte counter = 0x00;

        int pos = 0;
        while (pos < length)
        {
            if (counter != 0x00)
            {
                hmac.update(t, 0, t.length);
            }
            hmac.update(info, 0, info.length);
            hmac.update(new byte[]{ ++counter }, 0, 1);

            hmac.calculateMAC(t, 0);

            int copyLength = Math.min(hashLen, length - pos);
            System.arraycopy(t, 0, okm, pos, copyLength);
            pos += copyLength;
        }

        return adoptLocalSecret(okm);
    }

    public synchronized TlsSecret hkdfExtract(short hashAlgorithm, byte[] ikm)
    {
        checkAlive();

        byte[] salt = data;

        TlsCrypto crypto = getCrypto();
        TlsHMAC hmac = crypto.createHMAC(hashAlgorithm);

        hmac.setKey(salt, 0, salt.length);
        hmac.update(ikm, 0, ikm.length);

        byte[] prk = hmac.calculateMAC();

        return adoptLocalSecret(prk);
    }

    synchronized byte[] copyData()
    {
        return Arrays.clone(data);
    }
}
