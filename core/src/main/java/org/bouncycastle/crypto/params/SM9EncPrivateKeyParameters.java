package org.bouncycastle.crypto.params;

import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.util.Arrays;

/**
 * A user's SM9 encryption private key de = [t2]P2, a point of G2
 * (GM/T 0044.4-2016). Carries the master public key and the user's identity,
 * both needed to decapsulate/decrypt (the identity is part of the KDF input).
 */
public class SM9EncPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private final SM9G2Point de;
    private final SM9EncMasterPublicKeyParameters masterPublicKey;
    private final byte[] identity;

    SM9EncPrivateKeyParameters(SM9G2Point de, SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity)
    {
        super(true);
        this.de = de;
        this.masterPublicKey = masterPublicKey;
        this.identity = identity;
    }

    public SM9G2Point getPrivatePoint()
    {
        return de;
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
     * The user's encryption private key point de of G2 in uncompressed form
     * (0x04 || x || y, 129 bytes). The master public key and identity are not
     * part of this encoding; supply them via {@link #fromEncoded} to rebuild a
     * usable key (the identity is part of the decryption KDF input).
     */
    public byte[] getEncoded()
    {
        return de.getEncoded();
    }

    public static SM9EncPrivateKeyParameters fromEncoded(
        byte[] enc, SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity)
    {
        return new SM9EncPrivateKeyParameters(SM9G2Point.decode(enc), masterPublicKey, Arrays.clone(identity));
    }
}
