package org.bouncycastle.crypto.params;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.util.Integers;

/**
 * XMSS^MT Parameters.
 */
public final class XMSSMTParameters
    implements PQCParameters
{
    private static final Map<Integer, XMSSMTParameters> paramsLookupTable;

    static
    {
        Map<Integer, XMSSMTParameters> pMap = new HashMap<Integer, XMSSMTParameters>();

        // RFC 8391
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

        // SP 800-208: SHA-256/192 (n=24)
        pMap.put(Integers.valueOf(0x00000021), new XMSSMTParameters(20, 2, NISTObjectIdentifiers.id_sha256, 24));
        pMap.put(Integers.valueOf(0x00000022), new XMSSMTParameters(20, 4, NISTObjectIdentifiers.id_sha256, 24));
        pMap.put(Integers.valueOf(0x00000023), new XMSSMTParameters(40, 2, NISTObjectIdentifiers.id_sha256, 24));
        pMap.put(Integers.valueOf(0x00000024), new XMSSMTParameters(40, 4, NISTObjectIdentifiers.id_sha256, 24));
        pMap.put(Integers.valueOf(0x00000025), new XMSSMTParameters(40, 8, NISTObjectIdentifiers.id_sha256, 24));
        pMap.put(Integers.valueOf(0x00000026), new XMSSMTParameters(60, 3, NISTObjectIdentifiers.id_sha256, 24));
        pMap.put(Integers.valueOf(0x00000027), new XMSSMTParameters(60, 6, NISTObjectIdentifiers.id_sha256, 24));
        pMap.put(Integers.valueOf(0x00000028), new XMSSMTParameters(60, 12, NISTObjectIdentifiers.id_sha256, 24));

        // SP 800-208: SHAKE256/256 (n=32)
        pMap.put(Integers.valueOf(0x00000029), new XMSSMTParameters(20, 2, NISTObjectIdentifiers.id_shake256_len, 32));
        pMap.put(Integers.valueOf(0x0000002a), new XMSSMTParameters(20, 4, NISTObjectIdentifiers.id_shake256_len, 32));
        pMap.put(Integers.valueOf(0x0000002b), new XMSSMTParameters(40, 2, NISTObjectIdentifiers.id_shake256_len, 32));
        pMap.put(Integers.valueOf(0x0000002c), new XMSSMTParameters(40, 4, NISTObjectIdentifiers.id_shake256_len, 32));
        pMap.put(Integers.valueOf(0x0000002d), new XMSSMTParameters(40, 8, NISTObjectIdentifiers.id_shake256_len, 32));
        pMap.put(Integers.valueOf(0x0000002e), new XMSSMTParameters(60, 3, NISTObjectIdentifiers.id_shake256_len, 32));
        pMap.put(Integers.valueOf(0x0000002f), new XMSSMTParameters(60, 6, NISTObjectIdentifiers.id_shake256_len, 32));
        pMap.put(Integers.valueOf(0x00000030), new XMSSMTParameters(60, 12, NISTObjectIdentifiers.id_shake256_len, 32));

        // SP 800-208: SHAKE256/192 (n=24)
        pMap.put(Integers.valueOf(0x00000031), new XMSSMTParameters(20, 2, NISTObjectIdentifiers.id_shake256_len, 24));
        pMap.put(Integers.valueOf(0x00000032), new XMSSMTParameters(20, 4, NISTObjectIdentifiers.id_shake256_len, 24));
        pMap.put(Integers.valueOf(0x00000033), new XMSSMTParameters(40, 2, NISTObjectIdentifiers.id_shake256_len, 24));
        pMap.put(Integers.valueOf(0x00000034), new XMSSMTParameters(40, 4, NISTObjectIdentifiers.id_shake256_len, 24));
        pMap.put(Integers.valueOf(0x00000035), new XMSSMTParameters(40, 8, NISTObjectIdentifiers.id_shake256_len, 24));
        pMap.put(Integers.valueOf(0x00000036), new XMSSMTParameters(60, 3, NISTObjectIdentifiers.id_shake256_len, 24));
        pMap.put(Integers.valueOf(0x00000037), new XMSSMTParameters(60, 6, NISTObjectIdentifiers.id_shake256_len, 24));
        pMap.put(Integers.valueOf(0x00000038), new XMSSMTParameters(60, 12, NISTObjectIdentifiers.id_shake256_len, 24));

        paramsLookupTable = Collections.unmodifiableMap(pMap);
    }

    /**
     * The tallest hypertree whose leaves a long index can count. The per layer trees are bounded
     * separately, and more tightly, by {@link XMSSParameters#MAX_HEIGHT}.
     */
    public static final int MAX_HEIGHT = 62;

    private final int parameterSetOID;
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
        this(height, layers, XMSSEngine.getDigestOID(digest.getAlgorithmName()));
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
        this(height, layers, digestOID, -1);
    }

    /**
     * XMSSMT constructor with explicit security parameter n.
     *
     * @param height    Height of tree.
     * @param layers    Amount of layers.
     * @param digestOID Object identifier of digest to use.
     * @param n         Security parameter (digest output size in bytes), or -1 to derive from digest.
     */
    public XMSSMTParameters(int height, int layers, ASN1ObjectIdentifier digestOID, int n)
    {
        this.height = height;
        this.layers = layers;
        this.xmssParams = new XMSSParameters(xmssTreeHeight(height, layers), digestOID, n);
        parameterSetOID = XMSSEngine.lookupXMSSMTOid(getTreeDigest(), getTreeDigestSize(), getWinternitzParameter(),
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
        // the one time key index across the whole hypertree is a long, and isIndexValid() bounds
        // it by comparing against 1L << totalHeight, so a total height past this leaves that shift
        // negative or wrapped: every index reads as invalid at 63, and at 64 the maximum index
        // comes out as 0 - a key claiming 2^64 one time keys that in fact carries one
        if (height > MAX_HEIGHT)
        {
            throw new IllegalArgumentException("totalHeight must be <= " + MAX_HEIGHT);
        }
        // layers is a divisor below, and a zero one is an ArithmeticException rather than a
        // report of the parameter that was wrong; a negative one divides to a negative height,
        // which is then complained about as a height
        if (layers < 1)
        {
            throw new IllegalArgumentException("layers must be >= 1");
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

    public XMSSParameters getXMSSParameters()
    {
        return xmssParams;
    }

    public String getTreeDigest()
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
     * Return the NIST security category of this parameter set, as for
     * {@link XMSSParameters#getSecurityCategory()}.
     */
    public int getSecurityCategory()
    {
        return xmssParams.getSecurityCategory();
    }

    /**
     * Return the classical security strength of this parameter set, as for
     * {@link XMSSParameters#getClassicalSecurityStrength()}.
     */
    public int getClassicalSecurityStrength()
    {
        return xmssParams.getClassicalSecurityStrength();
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
     * Return the RFC 8391 / SP 800-208 parameter-set identifier for this parameter set (the 4-octet
     * value carried at the start of an RFC 9802 encoded key), or 0 if these parameters do not
     * correspond to a standard set (for example a non-standard tree height).
     *
     * @return the 4-octet parameter-set identifier, or 0 if none.
     */
    public int getParameterSetOID()
    {
        return parameterSetOID;
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

    public int getLen()
    {
        return xmssParams.getLen();
    }

    public static XMSSMTParameters lookupByOID(int oid)
    {
        return paramsLookupTable.get(Integers.valueOf(oid));
    }
}
