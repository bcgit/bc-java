package org.bouncycastle.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Integers;

/**
 * XMSS^MT Parameters.
 */
public final class XMSSMTParameters
{
    private static final Map<Integer, XMSSMTParameters> paramsLookupTable;

    static
    {
        Map<Integer, XMSSMTParameters> pMap = new HashMap<Integer, XMSSMTParameters>();

        pMap.put(Integers.valueOf(0x00000001), new XMSSMTParameters(20, 2, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(0x00000002), new XMSSMTParameters(20, 4, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(0x00000003), new XMSSMTParameters(40, 2, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(0x00000004), new XMSSMTParameters(40, 4, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(0x00000005), new XMSSMTParameters(40, 8, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(0x00000006), new XMSSMTParameters(60, 3, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(0x00000007), new XMSSMTParameters(60, 6, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(0x00000008), new XMSSMTParameters(60, 12, NISTObjectIdentifiers.id_sha256));
        pMap.put(Integers.valueOf(0x00000009), new XMSSMTParameters(20, 2, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(0x0000000a), new XMSSMTParameters(20, 4, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(0x0000000b), new XMSSMTParameters(40, 2, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(0x0000000c), new XMSSMTParameters(40, 4, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(0x0000000d), new XMSSMTParameters(40, 8, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(0x0000000e), new XMSSMTParameters(60, 3, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(0x0000000f), new XMSSMTParameters(60, 6, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(0x00000010), new XMSSMTParameters(60, 12, NISTObjectIdentifiers.id_sha512));
        pMap.put(Integers.valueOf(0x00000011), new XMSSMTParameters(20, 2, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(0x00000012), new XMSSMTParameters(20, 4, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(0x00000013), new XMSSMTParameters(40, 2, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(0x00000014), new XMSSMTParameters(40, 4, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(0x00000015), new XMSSMTParameters(40, 8, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(0x00000016), new XMSSMTParameters(60, 3, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(0x00000017), new XMSSMTParameters(60, 6, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(0x00000018), new XMSSMTParameters(60, 12, NISTObjectIdentifiers.id_shake128));
        pMap.put(Integers.valueOf(0x00000019), new XMSSMTParameters(20, 2, NISTObjectIdentifiers.id_shake256));
        pMap.put(Integers.valueOf(0x0000001a), new XMSSMTParameters(20, 4, NISTObjectIdentifiers.id_shake256));
        pMap.put(Integers.valueOf(0x0000001b), new XMSSMTParameters(40, 2, NISTObjectIdentifiers.id_shake256));
        pMap.put(Integers.valueOf(0x0000001c), new XMSSMTParameters(40, 4, NISTObjectIdentifiers.id_shake256));
        pMap.put(Integers.valueOf(0x0000001d), new XMSSMTParameters(40, 8, NISTObjectIdentifiers.id_shake256));
        pMap.put(Integers.valueOf(0x0000001e), new XMSSMTParameters(60, 3, NISTObjectIdentifiers.id_shake256));
        pMap.put(Integers.valueOf(0x0000001f), new XMSSMTParameters(60, 6, NISTObjectIdentifiers.id_shake256));
        pMap.put(Integers.valueOf(0x00000020), new XMSSMTParameters(60, 12, NISTObjectIdentifiers.id_shake256));
        paramsLookupTable = Collections.unmodifiableMap(pMap);
    }

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
        this(height, layers, DigestUtil.getDigestOID(digest.getAlgorithmName()));
    }

    /**
     * XMSSMT constructor...
     *
     * @param height Height of tree.
     * @param layers Amount of layers.
     * @param digestOID Object identifier of digest to use.
     */
    public XMSSMTParameters(int height, int layers, ASN1ObjectIdentifier digestOID)
    {
        super();
        this.height = height;
        this.layers = layers;
        this.xmssParams = new XMSSParameters(xmssTreeHeight(height, layers), digestOID);
        oid = DefaultXMSSMTOid.lookup(getTreeDigest(), getTreeDigestSize(), getWinternitzParameter(),
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

    protected String getTreeDigest()
    {
        return xmssParams.getTreeDigest();
    }

    /**
     * Getter digest size.
     *
     * @return Digest size.
     */
    public int getTreeDigestSize()
    {
        return xmssParams.getTreeDigestSize();
    }

    /**
     * Return the tree digest OID.
     *
     * @return OID for digest used to build the tree.
     */
    public ASN1ObjectIdentifier getTreeDigestOID()
    {
        return xmssParams.getTreeDigestOID();
    }

    /**
     * Getter Winternitz parameter.
     *
     * @return Winternitz parameter.
     */
    int getWinternitzParameter()
    {
        return xmssParams.getWinternitzParameter();
    }

    protected int getLen()
    {
        return xmssParams.getLen();
    }

    protected XMSSOid getOid()
    {
        return oid;
    }

    public static XMSSMTParameters lookupByOID(int oid)
    {
        return paramsLookupTable.get(Integers.valueOf(oid));
    }
}
