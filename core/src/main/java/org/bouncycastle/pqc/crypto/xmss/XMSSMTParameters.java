package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.Digest;

/**
 * XMSS^MT Parameters.
 */
public final class XMSSMTParameters
{

    private final XMSSOid oid;
    private final XMSSParameters xmssParams;
    private final int height;
    private final int layers;

    /**
     * XMSSMT constructor...
     *
     * @param height Height of tree.
     * @param layers Amount of layers.
     * @param digest Digest to use.
     */
    public XMSSMTParameters(int height, int layers, Digest digest)
    {
        super();
        this.height = height;
        this.layers = layers;
        this.xmssParams = new XMSSParameters(xmssTreeHeight(height, layers), digest);
        oid = DefaultXMSSMTOid.lookup(getDigest().getAlgorithmName(), getDigestSize(), getWinternitzParameter(),
            getLen(), getHeight(), layers);
        /*
		 * if (oid == null) { throw new InvalidParameterException(); }
		 */
    }

    private static int xmssTreeHeight(int height, int layers)
        throws IllegalArgumentException
    {
        if (height < 2)
        {
            throw new IllegalArgumentException("totalHeight must be > 1");
        }
        if (height % layers != 0)
        {
            throw new IllegalArgumentException("layers must divide totalHeight without remainder");
        }
        if (height / layers == 1)
        {
            throw new IllegalArgumentException("height / layers must be greater than 1");
        }
        return height / layers;
    }

    /**
     * Getter height.
     *
     * @return XMSSMT height.
     */
    public int getHeight()
    {
        return height;
    }

    /**
     * Getter layers.
     *
     * @return XMSSMT layers.
     */
    public int getLayers()
    {
        return layers;
    }

    protected XMSSParameters getXMSSParameters()
    {
        return xmssParams;
    }

    protected WOTSPlus getWOTSPlus()
    {
        return xmssParams.getWOTSPlus();
    }

    protected Digest getDigest()
    {
        return xmssParams.getDigest();
    }

    /**
     * Getter digest size.
     *
     * @return Digest size.
     */
    public int getDigestSize()
    {
        return xmssParams.getDigestSize();
    }

    /**
     * Getter Winternitz parameter.
     *
     * @return Winternitz parameter.
     */
    public int getWinternitzParameter()
    {
        return xmssParams.getWinternitzParameter();
    }

    protected int getLen()
    {
        return xmssParams.getWOTSPlus().getParams().getLen();
    }
}
