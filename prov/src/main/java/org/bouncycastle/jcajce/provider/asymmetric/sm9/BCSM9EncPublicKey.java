package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.InvalidObjectException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;

import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9EncUserPublicKey;
import org.bouncycastle.util.Arrays;

/**
 * An SM9 recipient's encryption public key: an encryption master public key together
 * with a recipient identity (GM/T 0044.4). It is the JCA counterpart of the lightweight
 * {@link SM9EncPublicKeyParameters}, and is supplied as the {@code PublicKey} of a
 * {@link org.bouncycastle.jcajce.spec.KEMGenerateSpec} when encapsulating a key to an
 * identity through {@code KeyGenerator.SM9-KEM}.
 * <p>
 * {@link #getIdentity()} and {@link #getMasterPublicKey()} return the two things this key
 * was derived from, so a caller need not track them separately.
 * <p>
 * Like the SM9 user identity keys this is a composite (master key + identity) handle
 * rather than a standalone-encodable key: {@code getEncoded()} returns {@code null}, and
 * it is not serializable on its own - persist the master public key and the identity
 * separately and reconstruct it.
 */
class BCSM9EncPublicKey
    implements SM9EncUserPublicKey
{
    private static final long serialVersionUID = 1L;

    private final transient SM9EncPublicKeyParameters keyParams;
    // one wrapper for the life of this key, so that getMasterPublicKey() == getMasterPublicKey()
    // holds as equals() does - it built a fresh wrapper on every call
    private final transient BCSM9EncMasterPublicKey masterPublicKey;

    BCSM9EncPublicKey(SM9EncPublicKeyParameters keyParams)
    {
        this.keyParams = keyParams;
        this.masterPublicKey = new BCSM9EncMasterPublicKey(keyParams.getMasterPublicKey());
    }

    SM9EncPublicKeyParameters getKeyParameters()
    {
        return keyParams;
    }

    public SM9EncMasterPublicKey getMasterPublicKey()
    {
        return masterPublicKey;
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
        return null;
    }

    public byte[] getEncoded()
    {
        return null;
    }

    /**
     * Two recipient keys are equal when they name the same master public key, the same
     * identity and the same hid. The hid is part of what the key <i>is</i>, not a label
     * on it: Q_B = [H1(identity || hid, N)]P1 + P_pub-e, so the keys for one identity
     * under two hids encrypt to two different points and neither one's private
     * counterpart opens the other's ciphertext.
     */
    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof BCSM9EncPublicKey))
        {
            return false;
        }
        BCSM9EncPublicKey other = (BCSM9EncPublicKey)o;
        return keyParams.getHid() == other.keyParams.getHid()
            && Arrays.areEqual(keyParams.getMasterPublicKey().getEncoded(),
                other.keyParams.getMasterPublicKey().getEncoded())
            && Arrays.areEqual(keyParams.getIdentity(), other.keyParams.getIdentity());
    }

    public int hashCode()
    {
        return 31 * (31 * Arrays.hashCode(keyParams.getMasterPublicKey().getEncoded())
                + Arrays.hashCode(keyParams.getIdentity()))
            + keyParams.getHid();
    }

    private Object writeReplace()
        throws ObjectStreamException
    {
        throw new NotSerializableException(
            "SM9 recipient public keys are not serializable standalone; persist the master public key and identity separately");
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
