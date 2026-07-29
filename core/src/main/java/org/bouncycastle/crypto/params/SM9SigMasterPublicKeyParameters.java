package org.bouncycastle.crypto.params;

import org.bouncycastle.math.ec.sm9.SM9G2Point;

/**
 * SM9 signature master public key P_pub-s = [ks]P2, a point of G2
 * (GM/T 0044.2-2016). Held by verifiers and used to derive users' public keys
 * from their identities.
 */
public class SM9SigMasterPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final SM9G2Point pPub;

    SM9SigMasterPublicKeyParameters(SM9G2Point pPub)
    {
        super(false);
        this.pPub = pPub;
    }

    public SM9G2Point getPointG2()
    {
        return pPub;
    }

    /**
     * The master public key point P_pub-s of G2 in uncompressed form
     * (0x04 || x || y, 129 bytes).
     */
    public byte[] getEncoded()
    {
        return pPub.getEncoded();
    }

    public static SM9SigMasterPublicKeyParameters fromEncoded(byte[] enc)
    {
        return new SM9SigMasterPublicKeyParameters(SM9G2Point.decode(enc));
    }
}
