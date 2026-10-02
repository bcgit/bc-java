package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9SigPrivateKeyParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * The SM9 identity-based digital signature algorithm (GM/T 0044.2-2016).
 * <p>
 * For signing, initialise with an {@link SM9SigPrivateKeyParameters} (optionally
 * wrapped in {@link ParametersWithRandom}). For verifying, initialise with an
 * {@link SM9SigMasterPublicKeyParameters} wrapped in a {@link ParametersWithID}
 * carrying the signer's identity.
 * <p>
 * The produced signature is encoded as h (32 bytes, big-endian) followed by the
 * uncompressed encoding of the G1 point S (0x04 || x || y), and that is the only
 * encoding verification accepts.
 * <p>
 * The message comes first in H2's input M || w, so it is hashed as update() is given it rather than
 * held until the signature is made or checked: each draw of the nonce, and verification, takes the
 * hash up from the state the message leaves.
 */
public class SM9Signer
    implements Signer
{
    /**
     * Draws of the nonce r allowed for one signature. A draw is discarded when it falls outside
     * [1, N-1], which a draw of N's bit length does with probability under 0.29, or when the scalar
     * l comes out zero, the standard's own retry, with probability about 2^-255. Needing this many
     * draws in a row has a probability below 2^-220, so reaching it means the random source is not
     * producing usable values rather than that the draws were unlucky.
     */
    private static final int MAX_REDRAWS = 128;

    /**
     * The bytes of H2's output that are kept: hlen = 8 * ceil(5 * log2(N) / 32) bits (GM/T 0044.2
     * 5.4.2.3), which SM9Sm3.h2 works out for any N, is 320 bits for this one - all of the first
     * output of SM3 and the leftmost 8 bytes of the second.
     */
    private static final int HLEN = 40;

    /**
     * A block of zeros, whose words and their expansion are all zero.
     */
    private static final byte[] ZEROS = new byte[64];

    // H2's input as far as it is known, from init on: its prefix 0x02 and the message given since
    private final SM3Digest digest = new SM3Digest();

    private boolean forSigning;
    private SM9SigPrivateKeyParameters signKey;
    private SM9SigMasterPublicKeyParameters verifyKey;
    private byte[] identity;
    private SecureRandom random;
    private Fp12 g;   // e(P1, P_pub-s), signing's base

    public void init(boolean forSigning, CipherParameters param)
    {
        // what the previous init installed is dropped before the new parameters are examined, so
        // that an init this goes on to refuse leaves the signer uninitialised - generateSignature
        // and verifySignature then say so - rather than still holding the last key for them to
        // use; the message pending from before goes with it, as it does on an init that succeeds
        this.forSigning = false;
        this.signKey = null;
        this.verifyKey = null;
        this.identity = null;
        this.random = null;
        this.g = null;
        restart();

        // ParametersWithID goes outside ParametersWithRandom - the order the crypto.params package
        // documentation gives, and the one SM2Signer takes - and the random source is unwrapped only
        // for signing. A chain nested the other way round, or carrying the same wrapper twice,
        // leaves a wrapper where the key should be and is refused below as a key of the wrong kind.
        CipherParameters base = param;
        byte[] id = null;
        if (base instanceof ParametersWithID)
        {
            // a copy rather than the caller's array: verifySignature reads the identity only
            // when it runs, so a caller that reused its array after init had its signatures
            // checked against whichever identity the array held by then
            id = Arrays.clone(((ParametersWithID)base).getID());
            base = ((ParametersWithID)base).getParameters();
        }

        SM9SigPrivateKeyParameters key = null;
        SM9SigMasterPublicKeyParameters master;
        SecureRandom random = null;
        if (forSigning)
        {
            if (base instanceof ParametersWithRandom)
            {
                random = ((ParametersWithRandom)base).getRandom();
                base = ((ParametersWithRandom)base).getParameters();
            }
            if (!(base instanceof SM9SigPrivateKeyParameters))
            {
                // named, as SM9Engine names the key it needs, rather than left to the cast below
                // to fail with a ClassCastException
                throw new IllegalArgumentException("SM9 signing requires an SM9SigPrivateKeyParameters user key");
            }
            key = (SM9SigPrivateKeyParameters)base;
            master = key.getMasterPublicKey();
        }
        else
        {
            if (!(base instanceof SM9SigMasterPublicKeyParameters))
            {
                throw new IllegalArgumentException(
                    "SM9 verification requires an SM9SigMasterPublicKeyParameters master public key");
            }
            if (id == null)
            {
                throw new IllegalArgumentException("SM9 verification requires the signer identity (ParametersWithID)");
            }
            if (id.length == 0)
            {
                // refused as the encryption side refuses it, and as the KGC does: no signing key
                // is derived for an empty identity, so no signature verifies under one
                throw new IllegalArgumentException("identity cannot be empty");
            }
            master = (SM9SigMasterPublicKeyParameters)base;
        }

        // g = e(P1, P_pub-s) is signing's base; verification takes its pairings as one product
        Fp12 pairing = forSigning ? master.pairingWithP1() : null;

        this.signKey = key;
        this.verifyKey = master;
        this.identity = id;
        this.random = forSigning ? CryptoServicesRegistrar.getSecureRandom(random) : null;
        this.g = pairing;
        this.forSigning = forSigning;
    }

    public void update(byte b)
    {
        digest.update(b);
    }

    public void update(byte[] in, int off, int len)
    {
        // a range outside the array is refused rather than left to SM3Digest, which takes a negative
        // length for none and would sign a message short of what was passed
        if (off < 0 || len < 0 || off > in.length - len)
        {
            throw new IndexOutOfBoundsException();
        }
        digest.update(in, off, len);
    }

    public byte[] generateSignature()
        throws CryptoException
    {
        if (!forSigning)
        {
            throw new IllegalStateException("SM9Signer not initialised for signing");
        }

        try
        {
            return sign();
        }
        finally
        {
            // the message is consumed however signing ends
            restart();
        }
    }

    private byte[] sign()
        throws CryptoException
    {
        // taken before any nonce is drawn: a key destroyed since init is reported through the
        // CryptoException generateSignature declares, not as the key's IllegalStateException
        ECPoint ds;
        try
        {
            ds = signKey.getPrivatePoint();
        }
        catch (IllegalStateException e)
        {
            throw new CryptoException("SM9 signing key destroyed", e);
        }

        BigInteger n = SM9Curve.N;
        BigInteger h;
        BigInteger l;
        for (int attempt = 0; ; ++attempt)
        {
            if (attempt == MAX_REDRAWS)
            {
                // GM/T 0044.2 6.1 A5 redraws r when l comes out zero and does not bound the
                // redraws, because each is independent with probability about 2^-255. A source that
                // yields nothing usable - only zeros, say - would make the loop spin rather than
                // fail, so it is bounded: reaching this many draws is not a chance event.
                throw new CryptoException("SM9 signing could not draw a usable nonce");
            }
            // A2: r in [1, N-1], drawn and range-checked here, where RandomDSAKCalculator redraws
            // an out-of-range value without limit and so never returned for such a source
            BigInteger r = BigIntegers.createRandomBigInteger(n.bitLength(), random);
            if (r.signum() == 0 || r.compareTo(n) >= 0)
            {
                continue;
            }
            Fp12 w = g.powSecureFixedBase(r);            // A3: w = g^r (r is the secret nonce)
            byte[] wb = SM9Pairing.toBytes(w);
            try
            {
                h = h2(wb);                              // A4: h = H2(M || w, N)
            }
            finally
            {
                Arrays.clear(wb);
            }
            // A5: l = (r - h) mod N, formed with the constant-time helper because r is the secret
            // nonce. r.subtract(h).mod(n) costs the reduction more work when the difference
            // underflows, which is the predicate r < h - and h travels in the signature, so that
            // is a public threshold on the secret r. h2 returns a value in [1, N-1] and the draw
            // above an r in [1, N-1], so both are inside the [0, N) the helper requires. The KGC's
            // own key derivation already uses these helpers on the master secret for the same
            // reason.
            l = BigIntegers.modSubtract(n, r, h);
            if (l.signum() != 0)
            {
                break;
            }
        }

        ECPoint s = SM9Curve.multiplySecure(ds, l).normalize();   // A6: S = [l]ds
        return encodeSignature(h, s);
    }

    public boolean verifySignature(byte[] signature)
    {
        if (forSigning || verifyKey == null)
        {
            // forSigning is false until an init says otherwise, so a signer never initialised
            // reached the key it does not have and failed with a NullPointerException
            throw new IllegalStateException("SM9Signer not initialised for verification");
        }

        try
        {
            return verify(signature);
        }
        finally
        {
            // the message is consumed however verification ends
            restart();
        }
    }

    private boolean verify(byte[] signature)
    {
        // h || 0x04 || x || y, exactly as generateSignature() writes it: decodePoint() would also
        // take S in the hybrid form (0x06 / 0x07 || x || y), a second encoding of every signature
        if (signature.length != 97 || signature[32] != 0x04)
        {
            return false;
        }

        BigInteger n = SM9Curve.N;
        BigInteger h = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));   // B1
        if (h.compareTo(ECConstants.ONE) < 0 || h.compareTo(n.subtract(ECConstants.ONE)) > 0)
        {
            return false;
        }

        // The catch covers the decode and nothing else. It used to span the whole body, the
        // pairing and the tower arithmetic included, so an internal arithmetic defect anywhere
        // in that chain would have presented as "this signature is invalid" rather than
        // surfacing - the shape this project's own conventions warn against. Past the decode
        // every value has been checked, and the two ways the algebra can still be undefined are
        // answered explicitly below.
        ECPoint s;
        try
        {
            s = SM9Curve.G1.decodePoint(Arrays.copyOfRange(signature, 32, signature.length));  // B2
        }
        catch (IllegalArgumentException e)
        {
            // a coordinate at or above q is not a field element: an invalid signature, not an error
            return false;
        }
        if (s.isInfinity() || !s.isValid())
        {
            return false;
        }

        BigInteger h1 = SM9Sm3.h1(Arrays.append(identity, SM9SigMasterPrivateKeyParameters.HID), n);  // B5

        // B4, B6 - B8: w' = u * t, with u = e(S, P), P = [h1]P2 + P_pub-s, and t = g^h for
        // g = e(P1, P_pub-s). By bilinearity that is e([h1]S, P2) e(S + [h]P1, P_pub-s), two
        // pairings of public points, which one Miller loop and one final exponentiation give in
        // place of a multiplication in G2, an exponentiation in G_T and a pairing. S + [h]P1 may be
        // the point at infinity, whose pairing is 1. So may P, for the identity the KGC can issue no
        // key for, H1(identity || hid, N) = -ks mod N: w' is then t alone, and verifies only an h
        // with H2(M || g^h, N) = h. [h]P1 goes through the fixed-point comb, over the table P1
        // keeps once it is built, where ECPoint.multiply doubles once for each bit of h, and [h1]S,
        // both of whose factors are public, through the GLV method, which doubles once for each
        // bit of a half of h1 about 128 bits long.
        ECPoint a = SM9Curve.multiplyPublic(s, h1);
        ECPoint b = s.add(new FixedPointCombMultiplier().multiply(SM9Curve.P1, h));
        Fp12 w = SM9Pairing.multiPair(new ECPoint[]{ a, b },
            new SM9G2Point[]{ SM9Curve.P2, verifyKey.getPointG2() });
        byte[] wb = SM9Pairing.toBytes(w);
        try
        {
            return h2(wb).equals(h);                                               // B9
        }
        finally
        {
            Arrays.clear(wb);
        }
    }

    public void reset()
    {
        restart();
    }

    /**
     * Start H2's input over, from its prefix 0x02, keeping nothing of the message before.
     * SM3Digest keeps the words of the block it is filling and of the last it compressed, and that
     * block's expansion, where its reset() does not reach; a block of zeros compressed first
     * overwrites them all with zeros.
     */
    private void restart()
    {
        digest.reset();
        digest.update(ZEROS, 0, ZEROS.length);
        digest.reset();
        digest.update((byte)0x02);
    }

    /**
     * H2(M || w, N) (GM/T 0044.2 5.4.2.3), for the message M the digest has been given: the leftmost
     * HLEN bytes of SM3(0x02 || M || w || 1) || SM3(0x02 || M || w || 2), the counter 32 bits
     * big-endian, reduced into [1, N-1], as SM9Sm3.h2 computes it from the whole input. The digest
     * is copied rather than finished, so that a nonce drawn again takes the hash up from the state
     * the message left, and each counter starts from a copy of the state w leaves, as the counters
     * of SM9Sm3 do.
     */
    private BigInteger h2(byte[] w)
    {
        SM3Digest sm3 = new SM3Digest(digest);
        sm3.update(w, 0, w.length);
        SM3Digest afterW = new SM3Digest(sm3);
        byte[] ha = new byte[HLEN];
        int ct = 1;
        for (int off = 0; off < HLEN; off += 32)
        {
            sm3.reset(afterW);
            sm3.update((byte)(ct >>> 24));
            sm3.update((byte)(ct >>> 16));
            sm3.update((byte)(ct >>> 8));
            sm3.update((byte)ct);
            if (HLEN - off >= 32)
            {
                sm3.doFinal(ha, off);
            }
            else
            {
                // doFinal always writes 32 bytes: the output wanted in part goes through a block of
                // its own, erased once the wanted bytes are copied out, as SM9Sm3 erases it
                byte[] last = new byte[32];
                sm3.doFinal(last, 0);
                System.arraycopy(last, 0, ha, off, HLEN - off);
                Arrays.clear(last);
            }
            ++ct;
        }
        // the copy holds the last words of w, which reset() would leave, and is overwritten from a
        // fresh digest, as SM9Sm3 overwrites its copy
        afterW.reset(new SM3Digest());

        // Ha, exactly hlen bits long, interpreted big-endian
        return new BigInteger(1, ha).mod(SM9Curve.N.subtract(ECConstants.ONE)).add(ECConstants.ONE);
    }

    private static byte[] encodeSignature(BigInteger h, ECPoint s)
    {
        return Arrays.concatenate(BigIntegers.asUnsignedByteArray(32, h), s.getEncoded(false));
    }
}
