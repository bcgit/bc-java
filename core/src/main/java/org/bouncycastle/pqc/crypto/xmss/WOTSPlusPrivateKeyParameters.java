package org.bouncycastle.pqc.crypto.xmss;

/**
 * WOTS+ private key.
 */
final class WOTSPlusPrivateKeyParameters
{

    private final byte[][] privateKey;

    protected WOTSPlusPrivateKeyParameters(WOTSPlusParameters params, byte[][] privateKey)
    {
        super();
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        if (privateKey == null)
        {
            throw new NullPointerException("privateKey == null");
        }
        if (XMSSUtil.hasNullPointer(privateKey))
        {
            throw new NullPointerException("privateKey byte array == null");
        }
        if (privateKey.length != params.getLen())
        {
            throw new IllegalArgumentException("wrong privateKey format");
        }
        for (int i = 0; i < privateKey.length; i++)
        {
            if (privateKey[i].length != params.getTreeDigestSize())
            {
                throw new IllegalArgumentException("wrong privateKey format");
            }
        }
        this.privateKey = XMSSUtil.cloneArray(privateKey);
    }

    protected byte[][] toByteArray()
    {
        return XMSSUtil.cloneArray(privateKey);
    }
}
