package org.bouncycastle.crypto.params;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.kems.frodo.FrodoKEMEngine;
import org.bouncycastle.util.Arrays;

public class FrodoKEMPrivateKeyParameters
    extends FrodoKEMKeyParameters
    implements Destroyable
{
    final byte[] privateKey;

    private volatile boolean destroyed;

    public FrodoKEMPrivateKeyParameters(FrodoKEMParameters params, byte[] privateKey)
    {
        super(true, params);

        if (privateKey.length != FrodoKEMEngine.getInstance(params).getPrivateKeySize())
        {
            throw new IllegalArgumentException("'privateKey' has invalid length");
        }

        this.privateKey = Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return cloneWithCheck(privateKey);
    }

    /**
     * Zeroize the secret key material held by this object.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;
            Arrays.clear(privateKey);
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }

    private byte[] cloneWithCheck(byte[] fieldValue)
    {
        byte[] rv = Arrays.clone(fieldValue);
        if (destroyed)
        {
            throw new IllegalStateException("key destroyed");
        }

        return rv;
    }
}
