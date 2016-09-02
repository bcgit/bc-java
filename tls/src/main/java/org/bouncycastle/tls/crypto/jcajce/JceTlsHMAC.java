package org.bouncycastle.tls.crypto.jcajce;

import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.tls.crypto.TlsHMAC;

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

    private final String algorithm;
    private final Integer internalBlockSize;

    private Mac hmac;

    public JceTlsHMAC(Mac hmac, String algorithm)
    {
        this.hmac = hmac;
        this.algorithm = algorithm;
        this.internalBlockSize = internalBlockSizes.get(algorithm);
        ;
    }

    public void setKey(byte[] key)
    {
        try
        {
            hmac.init(new SecretKeySpec(key, algorithm));
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
