package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * SM9 encryption master public key P_pub-e = [ke]P1, a point of G1
 * (GM/T 0044.4-2016). Note the group roles are swapped relative to signature:
 * the encryption master public key lives in G1 and users' keys in G2.
 */
public class SM9EncMasterPublicKeyParameters
    extends AsymmetricKeyParameter
{
    private final ECPoint pPube;
    // e(P_pub-e, P2), computed on first use - see pairingWithP2()
    private volatile Fp12 pairingWithP2;

    SM9EncMasterPublicKeyParameters(ECPoint pPube)
    {
        super(false);
        this.pPube = pPube;
    }

    /**
     * The encryption public key of the user identified by {@code identity}: the recipient key
     * a sender encapsulates to (or encrypts to), formed from this master public key and
     * the identity under the encryption hid 0x03 (GM/T 0044.4). It is derived from the
     * published master public key alone, so any sender can construct it without KGC
     * interaction.
     */
    public SM9EncPublicKeyParameters getUserPublicKey(byte[] identity)
    {
        return new SM9EncPublicKeyParameters(this, identity);
    }

    /**
     * The public key of the user identified by {@code identity} under an explicit hid -
     * use when the KGC's published hid differs from the encryption default
     * {@link SM9EncMasterPrivateKeyParameters#HID}. Any one byte is a legal hid;
     * {@code 0x03} and {@code 0x02} are the values the GM/T 0044 worked examples
     * publish for the encryption and key-exchange functions.
     * <p>
     * A key under {@link SM9EncMasterPrivateKeyParameters#HID_EXCHANGE} names a key-exchange
     * peer: {@link org.bouncycastle.crypto.engines.SM9Engine} and
     * {@link org.bouncycastle.crypto.kems.SM9KEMGenerator} refuse to encrypt or encapsulate to
     * it, since no decryption or decapsulation key can be derived under that hid.
     */
    public SM9EncPublicKeyParameters getUserPublicKey(byte[] identity, byte hid)
    {
        return new SM9EncPublicKeyParameters(this, identity, hid);
    }

    /**
     * Q = [H1(identity||hid, N)]P1 + P_pub-e, the recipient's public key point in G1,
     * using the encryption hid (0x03).
     */
    public ECPoint recipientPoint(byte[] identity)
    {
        return recipientPoint(identity, SM9EncMasterPrivateKeyParameters.HID);
    }

    /**
     * Q = [H1(identity||hid, N)]P1 + P_pub-e for an explicit hid (0x03 encryption,
     * 0x02 key exchange).
     * <p>
     * Encryption, encapsulation and the key exchange do not form Q: they form its multiple by their
     * ephemeral through {@link #multiplyRecipientPoint}.
     */
    public ECPoint recipientPoint(byte[] identity, byte hid)
    {
        SM9SigPrivateKeyParameters.checkContext(this, identity);
        BigInteger h1 = SM9Sm3.h1(Arrays.append(identity, hid), SM9Curve.N);
        // [h1]P1 through the fixed-point comb, over the table P1 keeps once it is built, where
        // ECPoint.multiply doubles once for each bit of h1
        ECPoint q = new FixedPointCombMultiplier().multiply(SM9Curve.P1, h1).add(pPube).normalize();
        if (q.isInfinity())
        {
            // [H1(identity || hid, N)]P1 = -P_pub-e, which is H1(identity || hid, N) = -ke mod N
            // and so t1 = 0 in the KGC's own derivation: the identity that reaches this point is
            // exactly the one no user key can be derived for, and the KGC refuses it with the
            // same message. Reached through an otherwise valid master public key - the infinity
            // guard there is on P_pub-e, not on this per-identity value - it used to leave the
            // sender with a NullPointerException out of the pairing instead.
            throw new IllegalArgumentException("SM9 encryption master key must be regenerated for this identity");
        }
        return q;
    }

    /**
     * [r]Q for Q = [H1(identity||hid, N)]P1 + P_pub-e, the point {@link #recipientPoint(byte[], byte)}
     * gives, and a <b>secret</b> r in [1, N-1]: the C1 = [r]Q_B that encryption and encapsulation send
     * (GM/T 0044.4-2016), and the R = [r]Q_peer the key exchange sends (GM/T 0044.3-2016). Q is not
     * formed: [r]Q is formed as [r h1 mod N]P1 + [r]P_pub-e, the product r h1 by
     * {@link BigIntegers#modMult}, in the same steps whatever r is, and the sum by
     * {@link SM9Curve#sumOfTwoMultipliesSecure}, one comb over P1's table and P_pub-e's, each
     * thirty-two multiples of the point and their doubles, 4 KB. P_pub-e's is made the first time
     * this key is multiplied and kept with it, as the powers of {@link #pairingWithP2()} are, so that
     * a sender holding one master public key for many recipients, and a party to many exchanges,
     * makes it once.
     *
     * @param identity the recipient's or the peer's identity.
     * @param hid the hid Q is formed under.
     * @param r the ephemeral, in [1, N-1].
     * @return [r]Q, in affine coordinates.
     * @throws IllegalArgumentException if r is not in [1, N-1], or if Q is the point at infinity,
     * as recipientPoint refuses it: [r]Q is then at infinity as well, and it is for no other Q.
     */
    public ECPoint multiplyRecipientPoint(byte[] identity, byte hid, BigInteger r)
    {
        SM9SigPrivateKeyParameters.checkContext(this, identity);
        if (r == null || r.signum() <= 0 || r.compareTo(SM9Curve.N) >= 0)
        {
            throw new IllegalArgumentException("SM9 ephemeral r must be in [1, N-1]");
        }
        BigInteger h1 = SM9Sm3.h1(Arrays.append(identity, hid), SM9Curve.N);
        ECPoint c = SM9Curve.sumOfTwoMultipliesSecure(SM9Curve.P1, BigIntegers.modMult(SM9Curve.N, r, h1), pPube, r)
            .normalize();
        if (c.isInfinity())
        {
            // [r]Q is the point at infinity exactly when Q is, N being prime and r not a multiple of
            // it: the identity recipientPoint refuses, for which no user key can be derived, refused
            // in the same terms
            throw new IllegalArgumentException("SM9 encryption master key must be regenerated for this identity");
        }
        return c;
    }

    /**
     * g = e(P_pub-e, P2), the fixed pairing value used by both encapsulation and
     * encryption.
     * <p>
     * It depends on this key alone, which is immutable, so it is computed once and kept: it is the
     * costliest single step of an encryption, an encapsulation or a key exchange, and a sender
     * holds one master public key for many of them. It involves no secret, so it is computed as
     * verification's pairings are, through {@link SM9Pairing#multiPair}, over the lines of P2's
     * Miller loop, which P2 keeps, where {@link SM9Pairing#pairing}, which is for a private key,
     * would compute them afresh from a random representative of P2 and give its final
     * exponentiation a random factor. Two threads asking for it first may both compute it, and get
     * equal values. Encryption, encapsulation and the key exchange raise it to each ephemeral
     * through {@link Fp12#powSecureFixedBase}, which keeps sixty-four powers of it with it, 24 KB,
     * once the first of them has made them.
     */
    public Fp12 pairingWithP2()
    {
        Fp12 g = pairingWithP2;
        if (g == null)
        {
            g = SM9Pairing.multiPair(new ECPoint[]{ pPube }, new SM9G2Point[]{ SM9Curve.P2 });
            pairingWithP2 = g;
        }
        return g;
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
        ECPoint pPube = SM9Curve.g1FromUncompressed(enc);
        if (pPube.isInfinity())
        {
            // [ke]P1 for ke in [1, N-1] never is; and e(P_pub-e, P2) would be the identity for it, making
            // every key encrypted or encapsulated to it a function of public values alone
            throw new IllegalArgumentException("SM9 encryption master public key cannot be the point at infinity");
        }
        return new SM9EncMasterPublicKeyParameters(pPube);
    }
}
