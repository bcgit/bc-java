package org.bouncycastle.pqc.crypto.xmss;

/**
 * WOTS+ public key.
 */
final class WOTSPlusPublicKeyParameters
{

    private final byte[][] publicKey;

    protected WOTSPlusPublicKeyParameters(WOTSPlusParameters params, byte[][] publicKey)
    {
        super();
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey == null");
        }
        if (XMSSUtil.hasNullPointer(publicKey))
        {
            throw new NullPointerException("publicKey byte array == null");
        }
        if (publicKey.length != params.getLen())
        {
            throw new IllegalArgumentException("wrong publicKey size");
        }
        for (int i = 0; i < publicKey.length; i++)
        {
            if (publicKey[i].length != params.getTreeDigestSize())
            {
                throw new IllegalArgumentException("wrong publicKey format");
            }
        }
        this.publicKey = XMSSUtil.cloneArray(publicKey);
    }

    protected byte[][] toByteArray()
    {
        return XMSSUtil.cloneArray(publicKey);
    }
}
