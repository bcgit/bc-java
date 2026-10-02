package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;

import javax.security.auth.Destroyable;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.jcajce.interfaces.SM9EncUserPrivateKey;

/**
 * JCA wrapper for a user's SM9 encryption (decryption) private key (de, a point
 * of G2), used with an SM9 {@link javax.crypto.Cipher} in DECRYPT_MODE. The
 * user's identity is carried within (it is part of the decryption KDF input) and
 * available via {@link #getIdentity()}, so a caller need not track it separately.
 * <p>
 * The JCA {@code getEncoded()} is a PKCS#8 PrivateKeyInfo under the GM algorithm OID
 * (the JCA convention); the bare GM/T 0080-2020 key bytes are available via the
 * lightweight key-parameter class's {@code getEncoded()}.
 */
class BCSM9EncPrivateKey
    implements SM9EncUserPrivateKey, Destroyable
{
    private static final long serialVersionUID = 1L;

    private final transient SM9EncPrivateKeyParameters keyParams;
    private final transient int hash;

    BCSM9EncPrivateKey(SM9EncPrivateKeyParameters keyParams)
    {
        this.keyParams = keyParams;
        // taken now, as the identity is erased with the key: a key destroyed while in a HashSet has
        // to go on hashing as it did when it went in
        this.hash = 31 * (31 * Arrays.hashCode(keyParams.getMasterPublicKey().getEncoded())
            + Arrays.hashCode(keyParams.getIdentity())) + keyParams.getHid();
    }

    SM9EncPrivateKeyParameters getKeyParameters()
    {
        return keyParams;
    }

    public byte[] getIdentity()
    {
        return keyParams.getIdentity();
    }

    public String getAlgorithm()
    {
        return "SM9-ENC";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        if (keyParams.isDestroyed())
        {
            throw new IllegalStateException("key destroyed");
        }

        try
        {
            PrivateKeyInfo info = new PrivateKeyInfo(
                new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), new DEROctetString(keyParams.getEncoded()));
            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to encode SM9 user decryption key", e);
        }
    }

    /**
     * Two user keys are equal when they carry the same secret point for the same identity,
     * under the same master public key, hid and usage. The encoding is the point alone, so
     * none of the others would be compared if they were left out: the hid and usage are what
     * tell the KEM / decryption key of an identity from its key-exchange key, which the
     * consumers refuse to use in each other's place, and {@link #hashCode()} is taken from
     * the master public key, so two keys equal without it could hash apart.
     * <p>
     * The public discriminators are compared first, in the ordinary way: they are the
     * KGC's published choices and the user's identity, not secrets. Only the point
     * comparison has to run in constant time.
     */
    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof BCSM9EncPrivateKey))
        {
            return false;
        }
        if (isDestroyed() || ((BCSM9EncPrivateKey)o).isDestroyed())
        {
            // getEncoded() throws once the key is destroyed, and Object.equals is contractually
            // non-throwing - a destroyed key in a HashSet would otherwise make contains() and
            // remove() blow up depending on which side of the comparison it landed on. It has no
            // key material left to compare, so it equals nothing but itself, which the identity
            // check above has already settled. hashCode() reads only public material and is
            // unaffected either way.
            return false;
        }
        BCSM9EncPrivateKey other = (BCSM9EncPrivateKey)o;
        if (keyParams.getHid() != other.keyParams.getHid()
            || keyParams.isExchangeKey() != other.keyParams.isExchangeKey()
            || !Arrays.areEqual(keyParams.getMasterPublicKey().getEncoded(),
                other.keyParams.getMasterPublicKey().getEncoded())
            || !Arrays.areEqual(keyParams.getIdentity(), other.keyParams.getIdentity()))
        {
            return false;
        }
        // both sides are the key parameters' own encodings of the secret, freshly made for this
        // comparison and erased once compared. The PKCS#8 encodings getEncoded() writes, which
        // were compared before, are made from these alone, so they compare as these do, but each
        // left further copies of the secret, in the ASN.1 objects and buffers that built it, which
        // nothing could erase
        byte[] mine = keyParams.getEncoded();
        byte[] theirs = other.keyParams.getEncoded();
        try
        {
            return Arrays.constantTimeAreEqual(mine, theirs);
        }
        finally
        {
            Arrays.clear(mine);
            Arrays.clear(theirs);
        }
    }

    public int hashCode()
    {
        // derived from the public master key, the identity and the hid, as the user public key's
        // is, never the secret key point: without the identity every user key of one KGC hashed
        // alike
        return hash;
    }

    /**
     * Destroy the underlying private point de (and the carried identity). After
     * destruction {@link #isDestroyed()} returns true, {@link #getEncoded()} throws
     * {@link IllegalStateException} and the key can no longer decapsulate/decrypt.
     */
    public synchronized void destroy()
    {
        keyParams.destroy();
    }

    public boolean isDestroyed()
    {
        return keyParams.isDestroyed();
    }

    private Object writeReplace()
        throws ObjectStreamException
    {
        throw new NotSerializableException(
            "SM9 user identity keys are not serializable standalone; re-derive from the master key via generateUserKeyPair");
    }

    /**
     * A key of this class is never written, as writeReplace says, so a stream that holds it was not
     * written by it: the key parameters are transient, and a key read from it would have none,
     * failing with a NullPointerException wherever it was used.
     */
    private void readObject(ObjectInputStream in)
        throws InvalidObjectException
    {
        throw new InvalidObjectException("SM9 user keys are not serializable");
    }
}
