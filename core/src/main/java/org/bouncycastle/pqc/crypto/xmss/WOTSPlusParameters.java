package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.Digest;

/**
 * WOTS+ Parameters.
 */
final class WOTSPlusParameters
{

    /**
     * OID.
     */
    private final XMSSOid oid;

    /**
     * The message digest size.
     */
    private final int digestSize;
    /**
     * The Winternitz parameter (currently fixed to 16).
     */
    private final int winternitzParameter;
    /**
     * The number of n-byte string elements in a WOTS+ secret key, public key,
     * and signature.
     */
    private final int len;
    /**
     * len1.
     */
    private final int len1;
    /**
     * len2.
     */
    private final int len2;
    private final ASN1ObjectIdentifier treeDigest;

    /**
     * Constructor...
     *
     * @param treeDigest The digest used for WOTS+.
     */
    protected WOTSPlusParameters(ASN1ObjectIdentifier treeDigest)
    {
        super();
        if (treeDigest == null)
        {
            throw new NullPointerException("treeDigest == null");
        }
        this.treeDigest = treeDigest;
        Digest digest = DigestUtil.getDigest(treeDigest);
        digestSize = XMSSUtil.getDigestSize(digest);
        winternitzParameter = 16;
        len1 = (int)Math.ceil((double)(8 * digestSize) / XMSSUtil.log2(winternitzParameter));
        len2 = (int)Math.floor(XMSSUtil.log2(len1 * (winternitzParameter - 1)) / XMSSUtil.log2(winternitzParameter)) + 1;
        len = len1 + len2;
        oid = WOTSPlusOid.lookup(digest.getAlgorithmName(), digestSize, winternitzParameter, len);
        if (oid == null)
        {
            throw new IllegalArgumentException("cannot find OID for digest algorithm: " + digest.getAlgorithmName());
        }
    }

    /**
     * Getter OID.
     *
     * @return WOTS+ OID.
     */
    protected XMSSOid getOid()
    {
        return oid;
    }
    
    /**
     * Getter digestSize.
     *
     * @return digestSize.
     */
    protected int getTreeDigestSize()
    {
        return digestSize;
    }

    /**
     * Getter WinternitzParameter.
     *
     * @return winternitzParameter.
     */
    protected int getWinternitzParameter()
    {
        return winternitzParameter;
    }

    /**
     * Getter len.
     *
     * @return len.
     */
    protected int getLen()
    {
        return len;
    }

    /**
     * Getter len1.
     *
     * @return len1.
     */
    protected int getLen1()
    {
        return len1;
    }

    /**
     * Getter len2.
     *
     * @return len2.
     */
    protected int getLen2()
    {
        return len2;
    }

    public ASN1ObjectIdentifier getTreeDigest()
    {
        return treeDigest;
    }
}
