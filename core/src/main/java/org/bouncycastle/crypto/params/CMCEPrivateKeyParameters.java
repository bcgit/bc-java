package org.bouncycastle.crypto.params;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.kems.cmce.CMCEEngine;
import org.bouncycastle.util.Arrays;

public class CMCEPrivateKeyParameters
    extends CMCEKeyParameters
    implements Destroyable
{
    final byte[] privateKey;

    private volatile boolean destroyed;

    public CMCEPrivateKeyParameters(CMCEParameters params, byte[] privateKey)
    {
        super(true, params);

        if (privateKey.length != CMCEEngine.getInstance(params).getPrivateKeySize())
        {
            throw new IllegalArgumentException("'privateKey' has invalid length");
        }

        this.privateKey = Arrays.clone(privateKey);
    }

    /**
     * @deprecated use getEncoded()
     */
    public byte[] getPrivateKey()
    {
        return getEncoded();
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
