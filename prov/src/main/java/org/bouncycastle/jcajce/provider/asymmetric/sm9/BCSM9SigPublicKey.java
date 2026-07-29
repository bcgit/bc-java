package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.NotSerializableException;
import java.io.ObjectStreamException;
import java.security.PublicKey;

import org.bouncycastle.crypto.params.SM9SigMasterPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * A user's SM9 signature public key: the signature master public key bound to the
 * user's identity (GM/T 0044.2). It is the key an {@code SM9}
 * {@link java.security.Signature} verifies against, obtained by a verifier from
 * {@link org.bouncycastle.jcajce.interfaces.SM9SigMasterPublicKey#getUserPublicKey(byte[])}.
 * <p>
 * Like the other SM9 user keys this is a composite (master key + identity) handle
 * rather than a standalone-encodable key: {@code getEncoded()} returns {@code null}, and
 * it is not serializable on its own - persist the master public key and the identity
 * separately and reconstruct it.
 */
public class BCSM9SigPublicKey
    implements PublicKey
{
    private static final long serialVersionUID = 1L;

    private final transient SM9SigMasterPublicKeyParameters masterParams;
    private final transient byte[] identity;

    BCSM9SigPublicKey(SM9SigMasterPublicKeyParameters masterParams, byte[] identity)
    {
        if (identity == null)
        {
            throw new NullPointerException("identity cannot be null");
        }
        this.masterParams = masterParams;
        this.identity = Arrays.clone(identity);
    }

    SM9SigMasterPublicKeyParameters getMasterPublicKeyParameters()
    {
        return masterParams;
    }

    byte[] getIdentity()
    {
        return Arrays.clone(identity);
    }

    public String getAlgorithm()
    {
        return "SM9-SIGN";
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
        if (!(o instanceof BCSM9SigPublicKey))
        {
            return false;
        }
        BCSM9SigPublicKey other = (BCSM9SigPublicKey)o;
        return Arrays.areEqual(masterParams.getEncoded(), other.masterParams.getEncoded())
            && Arrays.areEqual(identity, other.identity);
    }

    public int hashCode()
    {
        return 31 * Arrays.hashCode(masterParams.getEncoded()) + Arrays.hashCode(identity);
    }

    private Object writeReplace()
        throws ObjectStreamException
    {
        throw new NotSerializableException(
            "SM9 user public keys are not serializable standalone; persist the master public key and identity separately");
    }
}
