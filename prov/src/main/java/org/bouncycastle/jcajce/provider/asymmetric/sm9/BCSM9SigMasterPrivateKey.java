package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;
import java.security.KeyPair;

import javax.security.auth.Destroyable;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPrivateKey;

/**
 * JCA wrapper for an SM9 signature master private key (ks), held by the KGC.
 * Use {@link #generateUserKeyPair(byte[])} (a KGC operation, hid = 0x01) to derive
 * a user's key pair.
 * <p>
 * The JCA {@code getEncoded()} is a PKCS#8 PrivateKeyInfo under the GM algorithm OID
 * (the JCA convention); the bare GM/T 0080-2020 key bytes are available via the
 * lightweight key-parameter class's {@code getEncoded()}.
 * <p>
 * Like the provider's other private keys this one is serializable, written as that PKCS#8
 * encoding through {@link SM9KeyProxy} and rebuilt by the KeyFactory, so any object graph that
 * holds it and is serialized - a replicated session, a disk-backed cache - carries the master
 * secret with it. The SM9 user keys refuse serialization because their encoding cannot be
 * rebuilt without the master public key and identity, not because they are the more sensitive;
 * a KGC should keep this key out of structures that are serialized incidentally, and a destroyed
 * key refuses to serialize.
 */
class BCSM9SigMasterPrivateKey
    implements SM9SigMasterPrivateKey, Destroyable
{
    private static final long serialVersionUID = 1L;

    private final transient SM9SigMasterPrivateKeyParameters keyParams;

    BCSM9SigMasterPrivateKey(SM9SigMasterPrivateKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    SM9SigMasterPrivateKeyParameters getKeyParameters()
    {
        return keyParams;
    }

    private BCSM9SigPrivateKey extractPrivateKey(byte[] identity)
    {
        return new BCSM9SigPrivateKey(keyParams.generateUserKey(identity));
    }

    /**
     * Generate the key pair of the user identified by {@code identity}: the private key
     * that signs and the public key a verifier checks against (a KGC operation,
     * hid = 0x01).
     */
    public KeyPair generateUserKeyPair(byte[] identity)
    {
        return new KeyPair(
            new BCSM9SigPublicKey(keyParams.getPublicKeyParameters(), identity), extractPrivateKey(identity));
    }

    public String getAlgorithm()
    {
        return "SM9-SIGN";
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
                new AlgorithmIdentifier(GMObjectIdentifiers.sm9sign), new DEROctetString(keyParams.getEncoded()));
            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to encode SM9 master private key", e);
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof BCSM9SigMasterPrivateKey))
        {
            return false;
        }
        if (isDestroyed() || ((BCSM9SigMasterPrivateKey)o).isDestroyed())
        {
            // getEncoded() throws once the key is destroyed, and Object.equals is contractually
            // non-throwing - a destroyed key in a HashSet would otherwise make contains() and
            // remove() blow up depending on which side of the comparison it landed on. It has no
            // key material left to compare, so it equals nothing but itself, which the identity
            // check above has already settled. hashCode() reads only public material and is
            // unaffected either way.
            return false;
        }
        BCSM9SigMasterPrivateKey other = (BCSM9SigMasterPrivateKey)o;
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
        // derive from the public master key, never the secret ks
        return Arrays.hashCode(keyParams.getPublicKeyParameters().getEncoded());
    }

    /**
     * Destroy the underlying master secret ks. After destruction {@link #isDestroyed()}
     * returns true and the secret-bearing operations ({@link #getEncoded()},
     * {@link #generateUserKeyPair(byte[])}) throw {@link IllegalStateException};
     * user keys already derived are unaffected.
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
        if (keyParams.isDestroyed())
        {
            throw new NotSerializableException("key destroyed");
        }
        return new SM9KeyProxy(true, getEncoded());
    }

    /**
     * A key of this class is written as an SM9KeyProxy, never as itself, so a stream that holds the
     * class itself was not written by it: the key parameters are transient, and a key read from it
     * would have none, failing with a NullPointerException wherever it was used.
     */
    private void readObject(ObjectInputStream in)
        throws InvalidObjectException
    {
        throw new InvalidObjectException("SM9 master keys are read through their serialization proxy");
    }
}
