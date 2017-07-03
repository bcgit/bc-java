package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.Digest;

/**
 * XMSS Parameters.
 */
public final class XMSSParameters
{

    private final XMSSOid oid;
    private final WOTSPlus wotsPlus;
    //private final SecureRandom prng;
    private final int height;
    private final int k;

    /**
     * XMSS Constructor...
     *
     * @param height Height of tree.
     * @param digest Digest to use.
     */
    public XMSSParameters(int height, Digest digest)
    {
        super();
        if (height < 2)
        {
            throw new IllegalArgumentException("height must be >= 2");
        }
        if (digest == null)
        {
            throw new NullPointerException("digest == null");
        }

        wotsPlus = new WOTSPlus(new WOTSPlusParameters(digest));
        this.height = height;
        this.k = determineMinK();
        oid = DefaultXMSSOid.lookup(getDigest().getAlgorithmName(), getDigestSize(), getWinternitzParameter(),
            wotsPlus.getParams().getLen(), height);
        /*
		 * if (oid == null) { throw new InvalidParameterException(); }
		 */
    }

    private int determineMinK()
    {
        for (int k = 2; k <= height; k++)
        {
            if ((height - k) % 2 == 0)
            {
                return k;
            }
        }
        throw new IllegalStateException("should never happen...");
    }

    protected Digest getDigest()
    {
        return wotsPlus.getParams().getDigest();
    }

    /**
     * Getter digest size.
     *
     * @return Digest size.
     */
    public int getDigestSize()
    {
        return wotsPlus.getParams().getDigestSize();
    }

    /**
     * Getter Winternitz parameter.
     *
     * @return Winternitz parameter.
     */
    public int getWinternitzParameter()
    {
        return wotsPlus.getParams().getWinternitzParameter();
    }

    /**
     * Getter height.
     *
     * @return XMSS height.
     */
    public int getHeight()
    {
        return height;
    }

    WOTSPlus getWOTSPlus()
    {
        return wotsPlus;
    }

    int getK()
    {
        return k;
    }
}
