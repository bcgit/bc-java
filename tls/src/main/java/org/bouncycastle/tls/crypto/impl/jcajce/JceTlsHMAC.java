package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.tls.crypto.TlsHMAC;

/**
 * Wrapper class for a JCE MAC based on HMAC to provide the necessary operations for TLS.
 */
public class JceTlsHMAC
    implements TlsHMAC
{
    private static final Map<String, Integer> internalBlockSizes = new HashMap<String, Integer>();

    static
    {
        internalBlockSizes.put("HmacMD5", 64);
        internalBlockSizes.put("HmacSHA1", 64);
        internalBlockSizes.put("HmacSHA256", 64);
        internalBlockSizes.put("HmacSHA384", 128);
        internalBlockSizes.put("HmacSHA512", 128);
    }

    private final Mac hmac;
    private final String algorithm;
    private final Integer internalBlockSize;

    /**
     * Base constructor.
     *
     * @param hmac MAC implementation.
     * @param algorithm algorithm name to use for keys and to get the internal block size.
     */
    public JceTlsHMAC(Mac hmac, String algorithm)
    {
        this(hmac, algorithm, getInternalBlockSize(algorithm));
    }

    private static int getInternalBlockSize(String algorithm)
    {
        if (!internalBlockSizes.containsKey(algorithm))
        {
            throw new IllegalArgumentException("HMAC " + algorithm + " unknown");
        }

        return internalBlockSizes.get(algorithm);
    }

    /**
     * Base constructor specifying the internal block size.
     *
     * @param hmac MAC implementation.
     * @param algorithm algorithm name to use for keys and to get the internal block size.
     * @param internalBlockSize internal block size of the message digest underlying the HMAC.
     */
    public JceTlsHMAC(Mac hmac, String algorithm, int internalBlockSize)
    {
        this.hmac = hmac;
        this.algorithm = algorithm;
        this.internalBlockSize = internalBlockSize;
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        try
        {
            hmac.init(new SecretKeySpec(key, keyOff, keyLen, algorithm));
        }
        catch (InvalidKeyException e)
        {
            e.printStackTrace();
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
