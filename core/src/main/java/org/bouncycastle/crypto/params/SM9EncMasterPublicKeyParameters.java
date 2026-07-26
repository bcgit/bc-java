package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SM9Sm3;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;

/**
 * SM9 encryption master public key P_pub-e = [ke]P1, a point of G1
 * (GM/T 0044.4-2016). Note the group roles are swapped relative to signature:
 * the encryption master public key lives in G1 and users' keys in G2.
 */
public class SM9EncMasterPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final ECPoint pPube;

    SM9EncMasterPublicKeyParameters(ECPoint pPube)
    {
        super(false);
        this.pPube = pPube;
    }

    ECPoint getPointG1()
    {
        return pPube;
    }

    /**
     * The encryption public key of the user identified by {@code id}: the recipient key
     * a sender encapsulates to (or encrypts to), formed from this master public key and
     * the identity (GM/T 0044.4). It is derived from the published master public key
     * alone, so any sender can construct it without KGC interaction.
     */
    public SM9EncPublicKeyParameters getUserPublicKey(byte[] id)
    {
        return new SM9EncPublicKeyParameters(this, id);
    }

    /**
     * Q = [H1(id||hid, N)]P1 + P_pub-e, the recipient's public key point in G1,
     * using the encryption hid (0x03).
     */
    public ECPoint recipientPoint(byte[] identity)
    {
        return recipientPoint(identity, SM9EncMasterPrivateKeyParameters.HID);
    }

    /**
     * Q = [H1(id||hid, N)]P1 + P_pub-e for an explicit hid (0x03 encryption,
     * 0x02 key exchange).
     */
    public ECPoint recipientPoint(byte[] identity, byte hid)
    {
        BigInteger h1 = SM9Sm3.h1(Arrays.append(identity, hid), SM9Curve.N);
        return SM9Curve.P1.multiply(h1).add(pPube).normalize();
    }

    /**
     * g = e(P_pub-e, P2), the fixed pairing value used by both encapsulation and
     * encryption.
     */
    public Fp12 pairingWithP2()
    {
        return SM9Pairing.pairing(pPube, SM9Curve.P2);
    }

    /**
     * The master public key point P_pub-e of G1 in uncompressed form
     * (0x04 || x || y, 65 bytes).
     */
    public byte[] getEncoded()
    {
        return pPube.getEncoded(false);
    }

    public static SM9EncMasterPublicKeyParameters fromEncoded(byte[] enc)
    {
        return new SM9EncMasterPublicKeyParameters(SM9Curve.G1.decodePoint(enc));
    }
}
