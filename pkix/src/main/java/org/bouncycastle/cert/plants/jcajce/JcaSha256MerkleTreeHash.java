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
 *
 * <p>A fresh {@link MessageDigest} is created per call, so a single instance
 * is thread-safe and can be shared (e.g. inside an
 * {@link org.bouncycastle.cert.plants.MTCCertAuth} or a
 * {@link org.bouncycastle.cert.plants.MerkleTreeCertificateValidator.ValidationParams}
 * used by concurrent validations). The constructor fails fast if the selected
 * provider cannot supply SHA-256.</p>
 */
public class JcaSha256MerkleTreeHash
    implements MerkleTreeHash
{
    private static final AlgorithmIdentifier ALG_ID = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

    private final JcaJceHelper helper;
    private final int hashSize;

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
        this.helper = helper;
        this.hashSize = createDigest().getDigestLength();
    }

    private MessageDigest createDigest()
    {
        try
        {
            return helper.createDigest("SHA-256");
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to create SHA-256 digest: " + e.getMessage(), e);
        }
    }

    public int getHashSize()
    {
        return hashSize;
    }

    public byte[] hashLeaf(byte[] entry)
    {
        MessageDigest digest = createDigest();
        digest.update((byte)0x00);
        digest.update(entry, 0, entry.length);
        return digest.digest();
    }

    public byte[] hashNode(byte[] left, byte[] right)
    {
        MessageDigest digest = createDigest();
        digest.update((byte)0x01);
        digest.update(left, 0, left.length);
        digest.update(right, 0, right.length);
        return digest.digest();
    }

    public byte[] hashRaw(byte[] data)
    {
        MessageDigest digest = createDigest();
        digest.update(data, 0, data.length);
        return digest.digest();
    }
}
