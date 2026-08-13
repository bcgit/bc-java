package org.bouncycastle.crypto.agreement;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
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
 * (S_A).
 */
public class SM9KeyExchange
{
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
        this.key = key;
        this.peerIdentity = peerIdentity;
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
        ECPoint qPeer = key.getMasterPublicKey().recipientPoint(peerIdentity, key.getHid());
        SecureRandom rand = CryptoServicesRegistrar.getSecureRandom(random);
        ephemeralScalar = BigIntegers.createRandomInRange(
            ECConstants.ONE, SM9Curve.N.subtract(ECConstants.ONE), rand);
        ephemeralPoint = SM9Curve.multiplySecure(qPeer, ephemeralScalar).normalize();
        return ephemeralPoint;
    }


    /**
     * Compute the shared key of {@code klenBits} bits from the peer's ephemeral
     * value {@code peerR}. Must be called after {@link #generateEphemeral}.
     */
    public byte[] calculateKey(int klenBits, ECPoint peerR)
    {
        if (klenBits <= 0)
        {
            // match SM9KEMGenerator: a non-positive length has no KDF output
            throw new IllegalArgumentException("klenBits must be positive");
        }
        if (ephemeralPoint == null)
        {
            throw new IllegalStateException("generateEphemeral must be called first");
        }
        peerR = peerR.normalize();
        if (peerR.isInfinity() || !peerR.isValid())
        {
            throw new IllegalArgumentException("invalid SM9 peer ephemeral point");
        }

        BigInteger r = ephemeralScalar;
        Fp12 gPP = key.getMasterPublicKey().pairingWithP2();   // e(P_pub-e, P2)
        SM9G2Point de = key.getPrivatePoint();

        if (initiator)
        {
            g1 = gPP.powSecure(r);                             // e(P_pub-e,P2)^rA
            g2 = SM9Pairing.pairing(peerR, de);                // e(RB, deA)
            g3 = g2.powSecure(r);
        }
        else
        {
            g1 = SM9Pairing.pairing(peerR, de);                // e(RA, deB)
            g2 = gPP.powSecure(r);                             // e(P_pub-e,P2)^rB
            g3 = g1.powSecure(r);
        }

        identityA = initiator ? key.getIdentity() : peerIdentity;
        identityB = initiator ? peerIdentity : key.getIdentity();
        ECPoint ra = initiator ? ephemeralPoint : peerR;
        ECPoint rb = initiator ? peerR : ephemeralPoint;
        raBytes = SM9Curve.g1ToBytes(ra);
        rbBytes = SM9Curve.g1ToBytes(rb);

        ByteArrayOutputStream z = new ByteArrayOutputStream();
        write(z, identityA);
        write(z, identityB);
        write(z, raBytes);
        write(z, rbBytes);
        write(z, SM9Pairing.toBytes(g1));
        write(z, SM9Pairing.toBytes(g2));
        write(z, SM9Pairing.toBytes(g3));

        // GM/T 0044.3-2016 6.1 B5 and A7 derive SK with no all-zero rejection, unlike every KDF
        // site in 0044.4 (6.1.1 A6 and 7.1.1 A6 redraw r, 6.2.1 B3 and 7.2.1 B3 report an error).
        // That difference is deliberate, not an omission there or here.
        //
        // In 0044.4's stream mode K1 *is* the keystream and its length is the message length, so an
        // all-zero K1 gives C2 = M xor 0 = M - the plaintext in the clear - and at one byte of
        // message that is a 1-in-256 event rather than a negligible one; on the decrypt side the
        // length comes from the ciphertext, so an attacker reaches it in a few hundred tries. SK
        // here is negotiated key material the protocol never XORs with, and its length is the
        // caller's klenBits rather than a message length. Neither the consequence nor the rate
        // carries over, which is presumably why 0044.3 does not ask for the check.
        //
        // Do not "fix" this to match the 0044.4 sites: it would be strictness the standard does not
        // impose on a conformance-sensitive protocol path, and it would suggest one uniform rule
        // where the standard has two, for two different reasons.
        return SM9Sm3.kdf(z.toByteArray(), klenBits);
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
        update(sm3, SM9Pairing.toBytes(g2));
        update(sm3, SM9Pairing.toBytes(g3));
        update(sm3, identityA);
        update(sm3, identityB);
        update(sm3, raBytes);
        update(sm3, rbBytes);
        byte[] inner = new byte[32];
        sm3.doFinal(inner, 0);

        sm3.update(tag);
        update(sm3, SM9Pairing.toBytes(g1));
        update(sm3, inner);
        byte[] out = new byte[32];
        sm3.doFinal(out, 0);
        return out;
    }

    private static void write(ByteArrayOutputStream out, byte[] b)
    {
        out.write(b, 0, b.length);
    }

    private static void update(SM3Digest sm3, byte[] b)
    {
        sm3.update(b, 0, b.length);
    }
}
