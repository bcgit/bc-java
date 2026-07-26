package org.bouncycastle.crypto.params;

import org.bouncycastle.util.Arrays;

/**
 * An SM9 recipient's encryption public key: the identity together with the
 * encryption master public key from which the recipient point Q is derived
 * (GM/T 0044.4-2016). Obtained from
 * {@link SM9EncMasterPublicKeyParameters#getUserPublicKey(byte[])} and passed to the
 * {@link org.bouncycastle.crypto.kems.SM9KEMGenerator} when encapsulating a key to a
 * given identity.
 */
public class SM9EncPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final SM9EncMasterPublicKeyParameters masterPublicKey;
    private final byte[] identity;

    SM9EncPublicKeyParameters(SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity)
    {
        super(false);
        if (identity == null)
        {
            throw new NullPointerException("identity cannot be null");
        }
        this.masterPublicKey = masterPublicKey;
        this.identity = Arrays.clone(identity);
    }

    public SM9EncMasterPublicKeyParameters getMasterPublicKey()
    {
        return masterPublicKey;
    }

    public byte[] getIdentity()
    {
        return Arrays.clone(identity);
    }
}
