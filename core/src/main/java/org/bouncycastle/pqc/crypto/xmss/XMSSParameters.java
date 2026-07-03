package org.bouncycastle.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Integers;

/**
 * XMSS Parameters.
 */
public final class XMSSParameters
{
    private static final Map<Integer, XMSSParameters> paramsLookupTable;

    static
    {
        Map<Integer, XMSSParameters> pMap = new HashMap<Integer, XMSSParameters>();

        // RFC 8391
        pMap.put(Integers.valueOf(0x00000001), new XMSSParameters(10, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(0x00000002), new XMSSParameters(16, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(0x00000003), new XMSSParameters(20, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(0x00000004), new XMSSParameters(10, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(0x00000005), new XMSSParameters(16, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(0x00000006), new XMSSParameters(20, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(0x00000007), new XMSSParameters(10, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(0x00000008), new XMSSParameters(16, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(0x00000009), new XMSSParameters(20, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(0x0000000a), new XMSSParameters(10, NISTObjectIdentifiers.id_shake256));
        pMap.put(Integers.valueOf(0x0000000b), new XMSSParameters(16, NISTObjectIdentifiers.id_shake256));
        pMap.put(Integers.valueOf(0x0000000c), new XMSSParameters(20, NISTObjectIdentifiers.id_shake256));

        // SP 800-208: SHA-256/192 (n=24)
        pMap.put(Integers.valueOf(0x0000000d), new XMSSParameters(10, NISTObjectIdentifiers.id_sha256, 24));
        pMap.put(Integers.valueOf(0x0000000e), new XMSSParameters(16, NISTObjectIdentifiers.id_sha256, 24));
        pMap.put(Integers.valueOf(0x0000000f), new XMSSParameters(20, NISTObjectIdentifiers.id_sha256, 24));

        // SP 800-208: SHAKE256/256 (n=32)
        pMap.put(Integers.valueOf(0x00000010), new XMSSParameters(10, NISTObjectIdentifiers.id_shake256_len, 32));
        pMap.put(Integers.valueOf(0x00000011), new XMSSParameters(16, NISTObjectIdentifiers.id_shake256_len, 32));
        pMap.put(Integers.valueOf(0x00000012), new XMSSParameters(20, NISTObjectIdentifiers.id_shake256_len, 32));

        // SP 800-208: SHAKE256/192 (n=24)
        pMap.put(Integers.valueOf(0x00000013), new XMSSParameters(10, NISTObjectIdentifiers.id_shake256_len, 24));
        pMap.put(Integers.valueOf(0x00000014), new XMSSParameters(16, NISTObjectIdentifiers.id_shake256_len, 24));
        pMap.put(Integers.valueOf(0x00000015), new XMSSParameters(20, NISTObjectIdentifiers.id_shake256_len, 24));

        paramsLookupTable = Collections.unmodifiableMap(pMap);
    }

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
     * @param height     Height of tree.
     * @param treeDigest Digest to use.
     */
    public XMSSParameters(int height, Digest treeDigest)
    {
        this(height, DigestUtil.getDigestOID(treeDigest.getAlgorithmName()));
    }

    /**
     * XMSS Constructor...
     *
     * @param height     Height of tree.
     * @param treeDigestOID OID of digest to use.
     */
    public XMSSParameters(int height, ASN1ObjectIdentifier treeDigestOID)
    {
        this(height, treeDigestOID, -1);
    }

    /**
     * XMSS Constructor with explicit security parameter n.
     *
     * @param height        Height of tree.
     * @param treeDigestOID OID of digest to use.
     * @param n             Security parameter (digest output size in bytes), or -1 to derive from digest.
     */
    public XMSSParameters(int height, ASN1ObjectIdentifier treeDigestOID, int n)
    {
        super();
        if (height < 2)
        {
            throw new IllegalArgumentException("height must be >= 2");
        }
        if (treeDigestOID == null)
        {
            throw new NullPointerException("digest == null");
        }

        this.height = height;
        this.k = determineMinK();
        this.treeDigest = DigestUtil.getDigestName(treeDigestOID);
        this.treeDigestOID = treeDigestOID;

        if (n > 0)
        {
            this.wotsPlusParams = new WOTSPlusParameters(treeDigestOID, n);
        }
        else
        {
            this.wotsPlusParams = new WOTSPlusParameters(treeDigestOID);
        }
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
     * Return the tree digest OID.
     *
     * @return OID for digest used to build the tree.
     */
    public ASN1ObjectIdentifier getTreeDigestOID()
    {
        return treeDigestOID;
    }

    /**
     * Return the RFC 8391 / SP 800-208 parameter-set identifier for this parameter set (the 4-octet
     * value carried at the start of an RFC 9802 encoded key), or 0 if these parameters do not
     * correspond to a standard set (for example a non-standard tree height).
     *
     * @return the 4-octet parameter-set identifier, or 0 if none.
     */
    public int getParameterSetOID()
    {
        return (oid != null) ? oid.getOid() : 0;
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

    public static XMSSParameters lookupByOID(int oid)
    {
        return paramsLookupTable.get(Integers.valueOf(oid));
    }
}
