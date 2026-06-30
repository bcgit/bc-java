package org.bouncycastle.cert.plants.bc;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.plants.MerkleTreeHash;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * Lightweight SHA-256 implementation of {@link MerkleTreeHash}.
 *
 * <p>A fresh digest is created per call, so a single instance is thread-safe
 * and can be shared (e.g. inside an
 * {@link org.bouncycastle.cert.plants.MTCCertAuth} or a
 * {@link org.bouncycastle.cert.plants.MerkleTreeCertificateValidator.ValidationParams}
 * used by concurrent validations).</p>
 */
public class BcSha256MerkleTreeHash
    implements MerkleTreeHash
{
    private static final AlgorithmIdentifier ALG_ID = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return ALG_ID;
    }

    public int getHashSize()
    {
        return new SHA256Digest().getDigestSize();
    }

    public byte[] hashLeaf(byte[] entry)
    {
        Digest digest = new SHA256Digest();
        digest.update((byte)0x00);
        digest.update(entry, 0, entry.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    public byte[] hashNode(byte[] left, byte[] right)
    {
        Digest digest = new SHA256Digest();
        digest.update((byte)0x01);
        digest.update(left, 0, left.length);
        digest.update(right, 0, right.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    public byte[] hashRaw(byte[] data)
    {
        Digest digest = new SHA256Digest();
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }
}
