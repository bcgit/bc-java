package org.bouncycastle.jcajce.provider.asymmetric.xmss;

import java.security.InvalidAlgorithmParameterException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.signers.xmss.XMSSEngine;
import org.bouncycastle.jcajce.spec.XMSSParameterSpec;

class DigestUtil
{
    /**
     * What an {@link XMSSParameterSpec} tree-digest name names: the OID a key records for it, and
     * the security parameter n the parameter set uses it at - or -1 where that is the digest's own
     * output size, which is how the lightweight parameters read it.
     * <p>
     * The two are not separable. Neither says on its own which parameter set was asked for: the
     * SP 800-208 SHA-256/192 set shares id-sha256 with RFC 8391's SHA-256, and SHAKE256/256 and
     * SHAKE256/192 share id-shake256-len with each other, which is the same overlap
     * {@link #getXMSSDigestName(ASN1ObjectIdentifier, int)} below has to take both of to go the
     * other way.
     * </p>
     */
    static class TreeDigest
    {
        private final ASN1ObjectIdentifier oid;
        private final int n;

        TreeDigest(ASN1ObjectIdentifier oid, int n)
        {
            this.oid = oid;
            this.n = n;
        }

        ASN1ObjectIdentifier getOID()
        {
            return oid;
        }

        int getN()
        {
            return n;
        }
    }

    private static final Map<String, TreeDigest> treeDigests = new HashMap<String, TreeDigest>();

    static
    {
        treeDigests.put(XMSSParameterSpec.SHA256,
            new TreeDigest(NISTObjectIdentifiers.id_sha256, -1));
        treeDigests.put(XMSSParameterSpec.SHA512,
            new TreeDigest(NISTObjectIdentifiers.id_sha512, -1));
        treeDigests.put(XMSSParameterSpec.SHAKE128,
            new TreeDigest(NISTObjectIdentifiers.id_shake128, -1));
        treeDigests.put(XMSSParameterSpec.SHAKE256,
            new TreeDigest(NISTObjectIdentifiers.id_shake256, -1));
        treeDigests.put(XMSSParameterSpec.SHA256_192,
            new TreeDigest(NISTObjectIdentifiers.id_sha256, 24));
        treeDigests.put(XMSSParameterSpec.SHAKE256_256,
            new TreeDigest(NISTObjectIdentifiers.id_shake256_len, 32));
        treeDigests.put(XMSSParameterSpec.SHAKE256_192,
            new TreeDigest(NISTObjectIdentifiers.id_shake256_len, 24));
    }

    /**
     * The tree digest an {@link XMSSParameterSpec} names, for the two key pair generator SPIs.
     * <p>
     * They had this table each, seven branches in the same order saying the same thing, and the
     * only difference between the two copies was which parameter set class they went on to build -
     * so a digest added to one and not the other leaves the two families disagreeing about which
     * names exist. Building it as an OID and an n rather than as a Digest instance is what lets
     * the one table serve both: XMSSParameters and XMSSMTParameters take that pair, and the
     * instance the copies built for four of the seven was constructed only for the constructor to
     * read its algorithm name back off and look the OID up again.
     * </p>
     *
     * @param treeDigestName the name from the spec.
     * @throws InvalidAlgorithmParameterException if it is not one this provider knows.
     */
    static TreeDigest getTreeDigest(String treeDigestName)
        throws InvalidAlgorithmParameterException
    {
        TreeDigest treeDigest = treeDigests.get(treeDigestName);

        if (treeDigest == null)
        {
            throw new InvalidAlgorithmParameterException("unknown tree digest: " + treeDigestName);
        }

        return treeDigest;
    }

    /**
     * The tree-digest OID for a lightweight tree-digest name, including the SHAKE256-LEN of the
     * SP 800-208 SHAKE256/256 and SHAKE256/192 sets.
     * <p>
     * The names are the ones the lightweight key parameters report, so the table belongs to the
     * implementation that produces them rather than being kept a second time here: a copy of it
     * here was a copy that could be one parameter set behind. The digest-instance table beside
     * it, a third copy of the same five entries, had no caller at all.
     * </p>
     */
    static ASN1ObjectIdentifier getDigestOID(String digest)
    {
        return XMSSEngine.getDigestOID(digest);
    }

    public static byte[] getDigestResult(Digest digest)
    {
        byte[] hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        return hash;
    }

    public static String getXMSSDigestName(ASN1ObjectIdentifier treeDigest)
    {
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha256))
        {
            return XMSSParameterSpec.SHA256;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha512))
        {
            return XMSSParameterSpec.SHA512;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_shake128))
        {
            return XMSSParameterSpec.SHAKE128;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_shake256))
        {
            return XMSSParameterSpec.SHAKE256;
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + treeDigest);
    }

    /**
     * Tree-digest name including the security parameter, so the SP 800-208 sets are
     * distinguished from their RFC 8391 siblings sharing the same digest OID:
     * SHA-256/192 (n=24) shares id-sha256 with SHA-256/256 (n=32), and both SHAKE256/256
     * (n=32) and SHAKE256/192 (n=24) use id-shake256-len.
     *
     * @param treeDigest the tree-digest OID.
     * @param n          the security parameter (digest output size in bytes).
     */
    public static String getXMSSDigestName(ASN1ObjectIdentifier treeDigest, int n)
    {
        if (treeDigest.equals(NISTObjectIdentifiers.id_sha256))
        {
            return (n == 24) ? XMSSParameterSpec.SHA256_192 : XMSSParameterSpec.SHA256;
        }
        if (treeDigest.equals(NISTObjectIdentifiers.id_shake256_len))
        {
            return (n == 24) ? XMSSParameterSpec.SHAKE256_192 : XMSSParameterSpec.SHAKE256_256;
        }

        return getXMSSDigestName(treeDigest);
    }

    static class DoubleDigest
        implements Digest
    {
        private SHAKEDigest digest;

        DoubleDigest(SHAKEDigest digest)
        {
             this.digest = digest;
        }

        @Override
        public String getAlgorithmName()
        {
            return digest.getAlgorithmName() + "/" + (digest.getDigestSize() * 2 * 8);
        }

        @Override
        public int getDigestSize()
        {
            return digest.getDigestSize() * 2;
        }

        @Override
        public void update(byte in)
        {
             digest.update(in);
        }

        @Override
        public void update(byte[] in, int inOff, int len)
        {
            digest.update(in, inOff, len);
        }

        @Override
        public int doFinal(byte[] out, int outOff)
        {
            return digest.doFinal(out, outOff, this.getDigestSize());
        }

        @Override
        public void reset()
        {
            digest.reset();
        }
    }
}
