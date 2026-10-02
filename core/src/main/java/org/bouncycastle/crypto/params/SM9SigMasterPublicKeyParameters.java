package org.bouncycastle.crypto.params;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.math.ec.sm9.SM9Pairing;

/**
 * SM9 signature master public key P_pub-s = [ks]P2, a point of G2
 * (GM/T 0044.2-2016). Held by verifiers and used to derive users' public keys
 * from their identities.
 */
public class SM9SigMasterPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final SM9G2Point pPub;
    // e(P1, P_pub-s), computed on first use - see pairingWithP1()
    private volatile Fp12 pairingWithP1;

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
     * g = e(P1, P_pub-s), the fixed pairing value signing raises to its nonce. Verification does
     * not use it: it takes its w' as a single product of pairings, through
     * {@link SM9Pairing#multiPair}.
     * <p>
     * It depends on this key alone, which is immutable, so it is computed once and kept, as
     * {@link SM9EncMasterPublicKeyParameters#pairingWithP2()} keeps its counterpart: signing would
     * otherwise pay a pairing for it every time. It involves no secret, so it is computed as its
     * counterpart is, through {@link SM9Pairing#multiPair}, over the lines of P_pub-s's Miller loop,
     * which P_pub-s keeps, as it keeps them for verification. Two threads asking for it first may
     * both compute it, and get equal values. Signing raises it to each nonce through
     * {@link Fp12#powSecureFixedBase}, which keeps sixty-four powers of it with it, 24 KB, once the
     * first signature has made them.
     */
    public Fp12 pairingWithP1()
    {
        Fp12 g = pairingWithP1;
        if (g == null)
        {
            g = SM9Pairing.multiPair(new ECPoint[]{ SM9Curve.P1 }, new SM9G2Point[]{ pPub });
            pairingWithP1 = g;
        }
        return g;
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
