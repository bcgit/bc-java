package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.InvalidKeyException;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsHMAC;

/**
 * Wrapper class for a JCE MAC based on HMAC to provide the necessary operations for TLS.
 */
public class JceTlsHMAC
    implements TlsHMAC
{
    private final Mac hmac;
    private final String algorithm;
    private final int internalBlockSize;

    /**
     * Base constructor.
     *
     * @param cryptoHashAlgorithm the hash algorithm underlying the MAC implementation
     * @param hmac MAC implementation.
     * @param algorithm algorithm name to use for keys and to get the internal block size.
     */
    public JceTlsHMAC(int cryptoHashAlgorithm, Mac hmac, String algorithm)
    {
        this.hmac = hmac;
        this.algorithm = algorithm;
        this.internalBlockSize = TlsCryptoUtils.getHashInternalSize(cryptoHashAlgorithm);
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        try
        {
            hmac.init(new SecretKeySpec(key, keyOff, keyLen, algorithm));
        }
        catch (InvalidKeyException e)
        {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    public void update(byte[] input, int inOff, int length)
    {
        hmac.update(input, inOff, length);
    }

    public byte[] calculateMAC()
    {
        return hmac.doFinal();
    }

    public void calculateMAC(byte[] output, int outOff)
    {
        try
        {
            hmac.doFinal(output, outOff);
        }
        catch (ShortBufferException e)
        {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    public int getInternalBlockSize()
    {
        return internalBlockSize;
    }

    public int getMacLength()
    {
        return hmac.getMacLength();
    }

    public void reset()
    {
        hmac.reset();
    }
}
