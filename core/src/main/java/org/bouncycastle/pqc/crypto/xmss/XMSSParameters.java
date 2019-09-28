package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.Digest;

/**
 * XMSS Parameters.
 */
public final class XMSSParameters
{
    private final XMSSOid oid;
    private final int height;
    private final int k;
    private final ASN1ObjectIdentifier treeDigestOID;
    private final int winternitzParameter;
    private final String treeDigest;
    private final int treeDigestSize;
    private final WOTSPlusParameters wotsPlusParams;

    /**
     * XMSS Constructor...
     *
     * @param height Height of tree.
     * @param treeDigest Digest to use.
     */
    public XMSSParameters(int height, Digest treeDigest)
    {
        super();
        if (height < 2)
        {
            throw new IllegalArgumentException("height must be >= 2");
        }
        if (treeDigest == null)
        {
            throw new NullPointerException("digest == null");
        }

        this.height = height;
        this.k = determineMinK();
        this.treeDigest = treeDigest.getAlgorithmName();
        this.treeDigestOID = DigestUtil.getDigestOID(treeDigest.getAlgorithmName());

        this.wotsPlusParams = new WOTSPlusParameters(treeDigestOID);
        this.treeDigestSize = wotsPlusParams.getTreeDigestSize();
        this.winternitzParameter = wotsPlusParams.getWinternitzParameter();
        this.oid = DefaultXMSSOid.lookup(this.treeDigest, this.treeDigestSize, this.winternitzParameter, wotsPlusParams.getLen(), height);
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

    /**
     * Getter digest size.
     *
     * @return Digest size.
     */
    public int getTreeDigestSize()
    {
        return treeDigestSize;
    }

    /**
     * Getter height.
     *
     * @return XMSS tree height.
     */
    public int getHeight()
    {
        return height;
    }

    String getTreeDigest()
    {
        return treeDigest;
    }

    ASN1ObjectIdentifier getTreeDigestOID()
    {
        return treeDigestOID;
    }

    int getLen()
    {
        return wotsPlusParams.getLen();
    }

    /**
     * Getter Winternitz parameter.
     *
     * @return Winternitz parameter.
     */
    int getWinternitzParameter()
    {
        return winternitzParameter;
    }

    WOTSPlus getWOTSPlus()
    {
        return new WOTSPlus(wotsPlusParams);
    }

    XMSSOid getOid()
    {
        return oid;
    }

    int getK()
    {
        return k;
    }
}
