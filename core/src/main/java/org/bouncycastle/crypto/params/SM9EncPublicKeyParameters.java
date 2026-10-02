package org.bouncycastle.crypto.params;

import org.bouncycastle.util.Arrays;

/**
 * An SM9 recipient's encryption public key: the identity together with the
 * encryption master public key from which the recipient point Q is derived
 * (GM/T 0044.4-2016). Obtained from
 * {@link SM9EncMasterPublicKeyParameters#getUserPublicKey(byte[])} and passed to the
 * {@link org.bouncycastle.crypto.kems.SM9KEMGenerator} when encapsulating a key to a
 * given identity.
 * <p>
 * It is also what {@link org.bouncycastle.crypto.engines.SM9Engine} encrypts to.
 * <b>Usage warning:</b> an identity's key should be used for one of the two, but not for
 * both. Which of the two an identity's key is for is the KGC's to fix, by publishing a
 * separate hid for each function as it already does for the key exchange.
 */
public class SM9EncPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final SM9EncMasterPublicKeyParameters masterPublicKey;
    private final byte[] identity;
    private final byte hid;

    SM9EncPublicKeyParameters(SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity)
    {
        this(masterPublicKey, identity, SM9EncMasterPrivateKeyParameters.HID);
    }

    SM9EncPublicKeyParameters(SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity, byte hid)
    {
        super(false);
        SM9SigPrivateKeyParameters.checkContext(masterPublicKey, identity);
        this.masterPublicKey = masterPublicKey;
        this.identity = Arrays.clone(identity);
        this.hid = hid;
    }

    public SM9EncMasterPublicKeyParameters getMasterPublicKey()
    {
        return masterPublicKey;
    }

    public byte[] getIdentity()
    {
        return Arrays.clone(identity);
    }

    /**
     * The private-key generation function identifier hid this public key's Q
     * point is formed under - the KGC's published choice, {@code 0x03} for a
     * KEM / encryption recipient key.
     */
    public byte getHid()
    {
        return hid;
    }
}
