package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.InvalidKeyException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.tls.crypto.TlsMAC;

/**
 * A basic wrapper for a JCE Mac class to provide the needed functionality for TLS.
 */
public class JceTlsMAC
    implements TlsMAC
{
    private final String algorithm;

    private Mac mac;

    public JceTlsMAC(Mac mac, String algorithm)
    {
        this.mac = mac;
        this.algorithm = algorithm;
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        try
        {
            mac.init(new SecretKeySpec(key, keyOff, keyLen, algorithm));
        }
        catch (InvalidKeyException e)
        {
            e.printStackTrace();
        }
    }

    public void update(byte[] input, int inOff, int length)
    {
        mac.update(input, inOff, length);
    }

    public byte[] calculateMAC()
    {
        return mac.doFinal();
    }

    public int getMacLength()
    {
        return mac.getMacLength();
    }

    public void reset()
    {
        mac.reset();
    }
}
