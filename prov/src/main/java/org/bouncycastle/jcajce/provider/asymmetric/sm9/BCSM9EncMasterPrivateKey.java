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
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey;

/**
 * JCA wrapper for an SM9 encryption master private key (ke), held by the KGC.
 * Use {@link #generateUserKeyPair(byte[], byte)} (a KGC operation) to derive a
 * user's KEM / public-key encryption key pair under the KGC's published hid - 0x03 in
 * the published examples - and {@link #generateExchangeKeyPair(byte[])} for a
 * key-exchange pair, under 0x02.
 * <p>
 * The JCA {@code getEncoded()} is a PKCS#8 PrivateKeyInfo under the GM algorithm OID
 * (the JCA convention); the bare GM/T 0080-2020 key bytes are available via the
 * lightweight key-parameter class's {@code getEncoded()}.
 * <p>
 * Like the provider's other private keys this one is serializable, written as that PKCS#8
 * encoding through {@link SM9KeyProxy} and rebuilt by the KeyFactory, so any object graph that
 * holds it and is serialized - a replicated session, a disk-backed cache - carries the master
 * secret with it. The SM9 user keys refuse serialization because their encoding cannot be
 * rebuilt without the master public key, identity and hid, not because they are the more
 * sensitive; a KGC should keep this key out of structures that are serialized incidentally, and
 * a destroyed key refuses to serialize.
 */
class BCSM9EncMasterPrivateKey
    implements SM9EncMasterPrivateKey, Destroyable
{
    private static final long serialVersionUID = 1L;

    private final transient SM9EncMasterPrivateKeyParameters keyParams;

    BCSM9EncMasterPrivateKey(SM9EncMasterPrivateKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    /**
     * Generate the KEM / public-key encryption key pair of the user identified by
     * {@code identity} under the given hid (a KGC operation): the public key to encapsulate
     * or encrypt to and the private key that decapsulates or decrypts. The hid may not be
     * 0x02, which names the key exchange - a key-exchange pair comes from
     * {@link #generateExchangeKeyPair(byte[])}.
     */
    public KeyPair generateUserKeyPair(byte[] identity, byte hid)
    {
        return new KeyPair(
            new BCSM9EncPublicKey(keyParams.getPublicKeyParameters().getUserPublicKey(identity, hid)),
            new BCSM9EncPrivateKey(keyParams.generateUserKey(identity, hid)));
    }

    /**
     * Generate the key-exchange key pair of the user identified by {@code identity}
     * (a KGC operation), under hid 0x02 - see
     * {@link #generateExchangeKeyPair(byte[], byte)} for a KGC whose published
     * exchange hid differs.
     */
    public KeyPair generateExchangeKeyPair(byte[] identity)
    {
        return generateExchangeKeyPair(identity, SM9EncMasterPrivateKeyParameters.HID_EXCHANGE);
    }

    /**
     * Generate the key-exchange key pair of the user identified by {@code identity}
     * under the given hid (a KGC operation). The private half initialises
     * {@code KeyAgreement.SM9}; exchange keys and KEM/decryption keys are distinct
     * objects and the consumers mutually reject them.
     */
    public KeyPair generateExchangeKeyPair(byte[] identity, byte hid)
    {
        return new KeyPair(
            new BCSM9EncPublicKey(keyParams.getPublicKeyParameters().getUserPublicKey(identity, hid)),
            new BCSM9EncPrivateKey(keyParams.generateExchangeKey(identity, hid)));
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
            throw Exceptions.illegalStateException("unable to encode SM9 encryption master private key", e);
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof BCSM9EncMasterPrivateKey))
        {
            return false;
        }
        if (isDestroyed() || ((BCSM9EncMasterPrivateKey)o).isDestroyed())
        {
            // getEncoded() throws once the key is destroyed, and Object.equals is contractually
            // non-throwing - a destroyed key in a HashSet would otherwise make contains() and
            // remove() blow up depending on which side of the comparison it landed on. It has no
            // key material left to compare, so it equals nothing but itself, which the identity
            // check above has already settled. hashCode() reads only public material and is
            // unaffected either way.
            return false;
        }
        // both sides are the key parameters' own encodings of the secret, freshly made for this
        // comparison and erased once compared. The PKCS#8 encodings getEncoded() writes, which
        // were compared before, are made from these alone, so they compare as these do, but each
        // left further copies of the secret, in the ASN.1 objects and buffers that built it, which
        // nothing could erase
        byte[] mine = keyParams.getEncoded();
        byte[] theirs = ((BCSM9EncMasterPrivateKey)o).keyParams.getEncoded();
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
        // derive from the public master key, never the secret ke
        return Arrays.hashCode(keyParams.getPublicKeyParameters().getEncoded());
    }

    /**
     * Destroy the underlying master secret ke. After destruction {@link #isDestroyed()}
     * returns true and the secret-bearing operations ({@link #getEncoded()},
     * {@link #generateUserKeyPair(byte[], byte)}) throw {@link IllegalStateException};
     * user key pairs already generated are unaffected.
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
