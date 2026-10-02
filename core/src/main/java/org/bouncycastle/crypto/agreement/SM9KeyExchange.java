package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * The SM9 key exchange protocol (GM/T 0044.3-2016).
 * <p>
 * Usage per party: construct with your own key-exchange private key (derived under
 * the KGC's published hid), the peer's identity, and whether you are the initiator (user A) or
 * responder (user B). Call {@link #generateEphemeral} to produce your R value,
 * exchange R values, then call {@link #calculateKey} with the peer's R to obtain
 * the shared key. The optional key-confirmation tags are then available via
 * {@link #getResponderConfirmation()} (S_B) and {@link #getInitiatorConfirmation()}
 * (S_A), until a further {@link #generateEphemeral} begins another exchange.
 */
public class SM9KeyExchange
{
    /**
     * Draws of the ephemeral r allowed for one exchange. A draw is discarded when it falls outside
     * [1, N-1], which a draw of N's bit length does with probability under 0.29, so needing this many
     * in a row has a probability below 2^-220: reaching it means the random source is not producing
     * usable values rather than that the draws were unlucky.
     */
    private static final int MAX_REDRAWS = 128;

    private final SM9EncPrivateKeyParameters key;
    private final byte[] peerIdentity;
    private final boolean initiator;

    private BigInteger ephemeralScalar;
    private ECPoint ephemeralPoint;

    // retained after calculateKey for the confirmation tags
    private Fp12 g1;
    private Fp12 g2;
    private Fp12 g3;
    private byte[] identityA;
    private byte[] identityB;
    private byte[] raBytes;
    private byte[] rbBytes;

    public SM9KeyExchange(SM9EncPrivateKeyParameters key, byte[] peerIdentity, boolean initiator)
    {
        if (!key.isExchangeKey())
        {
            // the exchange pairs de with a peer-supplied point; a key that also
            // decapsulates would hand the peer a pairing oracle on de
            throw new IllegalArgumentException(
                "SM9 key exchange requires a key-exchange user key from generateExchangeKey");
        }
        if (peerIdentity == null)
        {
            throw new NullPointerException("peerIdentity cannot be null");
        }
        if (peerIdentity.length == 0)
        {
            throw new IllegalArgumentException("peerIdentity cannot be empty");
        }
        this.key = key;
        // a copy rather than the caller's array: the peer's identity forms Q_peer in
        // generateEphemeral and then goes into Z and both confirmation tags in calculateKey, so a
        // caller that reused its array between the two calls derived a key the peer did not
        this.peerIdentity = Arrays.clone(peerIdentity);
        this.initiator = initiator;
    }

    /**
     * Generate this party's ephemeral value R = [r]Q_peer (a G1 point) and retain
     * the ephemeral scalar r. Q_peer = [H1(peerIdentity||hid, N)]P1 + P_pub-e, using the
     * hid this party's own key was derived under - both parties' keys come from
     * the same KGC, which publishes the hid it chose.
     */
    public ECPoint generateEphemeral(SecureRandom random)
    {
        // a new exchange begins, and the confirmation tags of the last one no longer answer for
        // it: they are dropped, so that a tag asked for before this exchange's calculateKey is
        // refused rather than handed over from the exchange before
        g1 = null;
        g2 = null;
        g3 = null;
        identityA = null;
        identityB = null;
        raBytes = null;
        rbBytes = null;

        SecureRandom rand = CryptoServicesRegistrar.getSecureRandom(random);
        // A1 / B1: r in [1, N-1], drawn and range-checked here rather than by
        // BigIntegers.createRandomInRange, which after a thousand draws out of range falls back to
        // one that cannot fail - for a source that yields only zeros, r = 1
        BigInteger n = SM9Curve.N;
        BigInteger r;
        int attempt = 0;
        do
        {
            if (attempt++ == MAX_REDRAWS)
            {
                throw new IllegalStateException("SM9 key exchange could not draw a usable ephemeral");
            }
            r = BigIntegers.createRandomBigInteger(n.bitLength(), rand);
        }
        while (r.signum() == 0 || r.compareTo(n) >= 0);
        // R = [r]Q_peer, formed without forming Q_peer - see multiplyRecipientPoint, which refuses a
        // peer identity whose Q_peer is the point at infinity as recipientPoint does - and kept with r
        // only once it is formed
        ECPoint point = key.getMasterPublicKey().multiplyRecipientPoint(peerIdentity, key.getHid(), r);
        ephemeralScalar = r;
        ephemeralPoint = point;
        return ephemeralPoint;
    }


    /**
     * Compute the shared key of {@code klenBits} bits from the peer's ephemeral
     * value {@code peerR}. Must be called after {@link #generateEphemeral}.
     * <p>
     * {@code peerR} must be a point of SM9's own G1 - the curve is checked, not just the
     * curve equation the point carries with it.
     * <p>
     * The ephemeral answers exactly one peer value. GM/T 0044.3-2016 6.1 A2 and B2
     * draw a fresh r for each exchange, and one r combined with two peer values
     * yields two shared keys the same party legitimately agrees on, so this call
     * discards the ephemeral once it has derived a key: another exchange has to
     * begin with a further {@link #generateEphemeral}. The confirmation tags of the
     * exchange just completed remain available.
     */
    public byte[] calculateKey(int klenBits, ECPoint peerR)
    {
        if (klenBits <= 0)
        {
            // match SM9KEMGenerator: a non-positive length has no KDF output
            throw new IllegalArgumentException("klenBits must be positive");
        }
        if ((klenBits % 8) != 0)
        {
            // the key comes back as bytes and the KDF answers only a whole number of them; checked
            // here, before the ephemeral is combined with the peer value and discarded, rather than
            // letting the KDF refuse it afterwards
            throw new IllegalArgumentException("klenBits must be a whole number of bytes");
        }
        if (ephemeralPoint == null)
        {
            throw new IllegalStateException("generateEphemeral must be called first");
        }
        // isValid() alone answers against the point's own curve, so a point of an unrelated
        // curve - a NIST P-256 generator, say - passed it and went on to produce a "shared
        // key". The curve is checked first; with G1's cofactor 1, on-curve and not infinite
        // then settles membership of G1. The JCA path decodes 64 raw bytes onto G1 itself and
        // never had the gap.
        peerR = peerR.normalize();
        if (peerR.isInfinity() || !SM9Curve.G1.equals(peerR.getCurve()) || !peerR.isValid())
        {
            throw new IllegalArgumentException("invalid SM9 peer ephemeral point");
        }

        BigInteger r = ephemeralScalar;
        Fp12 gPP = key.getMasterPublicKey().pairingWithP2();   // e(P_pub-e, P2)
        SM9G2Point de = key.getPrivatePoint();

        // e(P_pub-e, P2) is public and kept with the master public key, so r raises it through the
        // comb over the table it keeps; the pairing with the peer's point is this exchange's own,
        // and r raises it through powSecure
        Fp12 v1, v2, v3;                                       // g1, g2, g3
        if (initiator)
        {
            v1 = gPP.powSecureFixedBase(r);                    // e(P_pub-e,P2)^rA
            v2 = SM9Pairing.pairing(peerR, de);                // e(RB, deA)
            v3 = v2.powSecure(r);
        }
        else
        {
            v1 = SM9Pairing.pairing(peerR, de);                // e(RA, deB)
            v2 = gPP.powSecureFixedBase(r);                    // e(P_pub-e,P2)^rB
            v3 = v1.powSecure(r);
        }
        byte[] ownIdentity = key.getIdentity();
        byte[] ra = SM9Curve.g1ToBytes(initiator ? ephemeralPoint : peerR);
        byte[] rb = SM9Curve.g1ToBytes(initiator ? peerR : ephemeralPoint);

        // what the confirmation tags read is set only once all of it is formed, as they take g1
        // being set for the whole: a call failing between one assignment and the next - a draw from
        // the default source failing in the pairing, say - had left tags that threw
        // NullPointerException, where they refuse an exchange that has not completed
        g1 = v1;
        g2 = v2;
        g3 = v3;
        identityA = initiator ? ownIdentity : peerIdentity;
        identityB = initiator ? peerIdentity : ownIdentity;
        raBytes = ra;
        rbBytes = rb;

        // r has now been combined with a peer value: drop it, so a further exchange on this object
        // has to draw a fresh one rather than answer a second peer value with the same ephemeral.
        // The tags read raBytes / rbBytes, taken above, so they are unaffected.
        ephemeralScalar = null;
        ephemeralPoint = null;

        // Z = ID_A || ID_B || R_A || R_B || g1 || g2 || g3, built in arrays this method can erase:
        // g1, g2 and g3 are the secret the shared key is derived from, and a ByteArrayOutputStream
        // would have kept them in a backing array nothing clears. Z is assembled in a single call
        // for the same reason: joining g1b, g2b and g3b first would leave an intermediate copy of
        // them that nothing erases.
        byte[] g1b = SM9Pairing.toBytes(g1);
        byte[] g2b = SM9Pairing.toBytes(g2);
        byte[] g3b = SM9Pairing.toBytes(g3);
        byte[] z = Arrays.concatenate(
            new byte[][]{ identityA, identityB, raBytes, rbBytes, g1b, g2b, g3b });

        // GM/T 0044.3-2016 6.1 B5 and A7 derive SK with no all-zero check, unlike the KDF sites of
        // 0044.4 (6.1.1 A6 and 7.1.1 A6 redraw r, 6.2.1 B3 and 7.2.1 B3 report an error). The
        // difference is the standard's and is kept here: do not add the check to match the 0044.4
        // sites. Both parties derive SK from the same input, so a check 0044.3 does not ask for
        // would fail an exchange that a peer following the standard completes.
        try
        {
            return SM9Sm3.kdf(z, klenBits);
        }
        finally
        {
            Arrays.clear(z);
            Arrays.clear(g1b);
            Arrays.clear(g2b);
            Arrays.clear(g3b);
        }
    }

    /**
     * S_B = Hash(0x82 || g1 || Hash(g2||g3||IDA||IDB||RA||RB)): the confirmation
     * the responder sends to (and the initiator checks against) the initiator.
     * <p>
     * The returned tag is a secret authenticator; a received value must be compared
     * against it with {@link org.bouncycastle.util.Arrays#constantTimeAreEqual(byte[], byte[])},
     * not {@code Arrays.equals}, to avoid a timing side channel.
     */
    public byte[] getResponderConfirmation()
    {
        return confirmation((byte)0x82);
    }

    /**
     * S_A = Hash(0x83 || g1 || Hash(g2||g3||IDA||IDB||RA||RB)): the confirmation
     * the initiator sends to (and the responder checks against) the responder.
     * <p>
     * The returned tag is a secret authenticator; a received value must be compared
     * against it with {@link org.bouncycastle.util.Arrays#constantTimeAreEqual(byte[], byte[])},
     * not {@code Arrays.equals}, to avoid a timing side channel.
     */
    public byte[] getInitiatorConfirmation()
    {
        return confirmation((byte)0x83);
    }

    private byte[] confirmation(byte tag)
    {
        if (g1 == null)
        {
            throw new IllegalStateException("calculateKey must be called first");
        }
        SM3Digest sm3 = new SM3Digest();
        update(sm3, g2);
        update(sm3, g3);
        update(sm3, identityA);
        update(sm3, identityB);
        update(sm3, raBytes);
        update(sm3, rbBytes);
        byte[] inner = new byte[32];
        sm3.doFinal(inner, 0);

        sm3.update(tag);
        update(sm3, g1);
        update(sm3, inner);
        // inner is a hash over g2 and g3, two of the values the shared key is derived from: erased
        // once the digest has taken it, as their serialised copies are
        Arrays.clear(inner);
        byte[] out = new byte[32];
        sm3.doFinal(out, 0);
        return out;
    }

    private static void update(SM3Digest sm3, byte[] b)
    {
        sm3.update(b, 0, b.length);
    }

    /**
     * Feed a pairing value to the digest. g1, g2 and g3 are the secret the shared key is derived
     * from, so the array it is serialised into is erased once the digest has taken it, as
     * calculateKey erases its copies.
     */
    private static void update(SM3Digest sm3, Fp12 g)
    {
        byte[] b = SM9Pairing.toBytes(g);
        update(sm3, b);
        Arrays.clear(b);
    }
}
