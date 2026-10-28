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
 * XMSS Parameters.
 */
public final class XMSSParameters
    implements PQCParameters
{
    private static final Map<Integer, XMSSParameters> paramsLookupTable;
    /**
     * The Winternitz parameter, fixed at 16 by RFC 8391 sec. 5.
     */
    private static final int WINTERNITZ_PARAMETER = 16;
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

    /**
     * The tallest tree whose leaves an int index can count. Shared with BDS.validate(), which
     * refuses a traversal state outside it.
     */
    public static final int MAX_HEIGHT = 30;

    private final int parameterSetOID;
    private final int height;
    private final int k;
    private final ASN1ObjectIdentifier treeDigestOID;

    private final String treeDigest;
    private final int treeDigestSize;
    private final int len;

    /**
     * XMSS Constructor...
     *
     * @param height     Height of tree.
     * @param treeDigest Digest to use.
     */
    public XMSSParameters(int height, Digest treeDigest)
    {
        this(height, XMSSEngine.getDigestOID(treeDigest.getAlgorithmName()));
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
        if (height < 2)
        {
            throw new IllegalArgumentException("height must be >= 2");
        }
        // the one time key index, and the maximum index bounding it, are both ints, so a tree
        // taller than this cannot count its own leaves: (1 << height) - 1 wraps. It wraps to a
        // negative for a height 31 above a multiple of 32, which leaves the traversal state with
        // no leaves to build from and surfaces as an EmptyStackException out of key generation,
        // and to a smaller positive for most of the rest, which is worse - the key generated is a
        // shorter tree than the one asked for, with nothing to say so. BDS.validate() refuses a
        // state outside the same bound on the way back in.
        if (height > MAX_HEIGHT)
        {
            throw new IllegalArgumentException("height must be <= " + MAX_HEIGHT);
        }
        if (treeDigestOID == null)
        {
            throw new NullPointerException("digest == null");
        }

        this.height = height;
        this.k = determineMinK();
        this.treeDigest = XMSSEngine.getDigestName(treeDigestOID);
        this.treeDigestOID = treeDigestOID;

        this.treeDigestSize = (n > 0) ? n : XMSSEngine.getDigestSize(treeDigestOID);
        this.len = XMSSEngine.getWOTSPlusLen(treeDigestOID, this.treeDigestSize);
        this.parameterSetOID = XMSSEngine.lookupXMSSOid(this.treeDigest, this.treeDigestSize, WINTERNITZ_PARAMETER, this.len, height);
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
     * Return the NIST security category of this parameter set: 3 for the SHA-256/192 and
     * SHAKE256/192 sets (n = 24) and 5 for the SHA-256 and SHAKE256/256 sets (n = 32)
     * (NIST IR 8547, Table 3, for the sets approved in SP 800-208). The RFC 8391 sets outside
     * SP 800-208 (SHA-512, SHAKE128 and SHAKE256/512) are given the figure their hash output
     * length implies and carry no NIST categorisation.
     */
    public int getSecurityCategory()
    {
        return (treeDigestSize <= 24) ? 3 : 5;
    }

    /**
     * Return the classical security strength of this parameter set: 8 times the hash output
     * length n, capped at 256 bits (NIST IR 8547, Table 3).
     */
    public int getClassicalSecurityStrength()
    {
        return Math.min(256, 8 * treeDigestSize);
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
        return parameterSetOID;
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

    public String getTreeDigest()
    {
        return treeDigest;
    }

    public int getLen()
    {
        return len;
    }

    /**
     * Getter Winternitz parameter.
     *
     * @return Winternitz parameter.
     */
    public int getWinternitzParameter()
    {
        return WINTERNITZ_PARAMETER;
    }

    public int getK()
    {
        return k;
    }

    public static XMSSParameters lookupByOID(int oid)
    {
        return paramsLookupTable.get(Integers.valueOf(oid));
    }
}
