package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.NotSerializableException;
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

    BCSM9EncPublicKey(SM9EncPublicKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    SM9EncPublicKeyParameters getKeyParameters()
    {
        return keyParams;
    }

    @Override
    public SM9EncMasterPublicKey getMasterPublicKey()
    {
        return new BCSM9EncMasterPublicKey(keyParams.getMasterPublicKey());
    }

    @Override
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
        return Arrays.areEqual(keyParams.getMasterPublicKey().getEncoded(),
                other.keyParams.getMasterPublicKey().getEncoded())
            && Arrays.areEqual(keyParams.getIdentity(), other.keyParams.getIdentity());
    }

    public int hashCode()
    {
        return 31 * Arrays.hashCode(keyParams.getMasterPublicKey().getEncoded())
            + Arrays.hashCode(keyParams.getIdentity());
    }

    private Object writeReplace()
        throws ObjectStreamException
    {
        throw new NotSerializableException(
            "SM9 recipient public keys are not serializable standalone; persist the master public key and identity separately");
    }
}
