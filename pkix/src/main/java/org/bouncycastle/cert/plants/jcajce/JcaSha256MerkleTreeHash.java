package org.bouncycastle.cert.plants.jcajce;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.plants.MerkleTreeHash;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.util.Exceptions;

/**
 * JCA-side SHA-256 implementation of {@link MerkleTreeHash}, obtained via
 * {@code MessageDigest.getInstance("SHA-256")} through a {@link JcaJceHelper}.
 */
public class JcaSha256MerkleTreeHash
    implements MerkleTreeHash
{
    private static final AlgorithmIdentifier ALG_ID = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

    private final MessageDigest digest;

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return ALG_ID;
    }

    public JcaSha256MerkleTreeHash()
    {
        this(new DefaultJcaJceHelper());
    }

    public JcaSha256MerkleTreeHash(String providerName)
    {
        this(new NamedJcaJceHelper(providerName));
    }

    public JcaSha256MerkleTreeHash(Provider provider)
    {
        this(new ProviderJcaJceHelper(provider));
    }

    public JcaSha256MerkleTreeHash(JcaJceHelper helper)
    {
        try
        {
            this.digest = helper.createDigest("SHA-256");
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to create SHA-256 digest: " + e.getMessage(), e);
        }
    }

    public int getHashSize()
    {
        return digest.getDigestLength();
    }

    public byte[] hashLeaf(byte[] entry)
    {
        digest.reset();
        digest.update((byte)0x00);
        digest.update(entry, 0, entry.length);
        return digest.digest();
    }

    public byte[] hashNode(byte[] left, byte[] right)
    {
        digest.reset();
        digest.update((byte)0x01);
        digest.update(left, 0, left.length);
        digest.update(right, 0, right.length);
        return digest.digest();
    }

    public byte[] hashRaw(byte[] data)
    {
        digest.reset();
        digest.update(data, 0, data.length);
        return digest.digest();
    }
}
