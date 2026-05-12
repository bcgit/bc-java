package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * BLS signatures BasicScheme over BLS12-381, per draft-irtf-cfrg-bls-signature
 * (variant: public keys in G1, signatures in G2; suite
 * {@code BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_}).
 * <p>
 * Provides the algorithmic core: KeyGen, SkToPk, Sign, Verify, KeyValidate,
 * and aggregate verification. The static API operates on in-memory math
 * objects ({@code BigInteger} secret keys, {@link ECPoint} public keys,
 * byte-array messages, {@link BLS12_381G2Point} signatures);
 * {@link BLS12_381Serialization} converts to and from the spec's
 * Zcash-format compressed encodings.
 */
public class BLS12_381BasicScheme
{
    /**
     * Domain-separation tag for hash-to-curve under the BasicScheme suite.
     */
    public static final byte[] DST = Strings.toUTF8ByteArray(
        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_");

    /** Initial salt for {@link #keyGen} per draft-irtf-cfrg-bls-signature sec. 2.3. */
    private static final byte[] KEYGEN_SALT_INIT = Strings.toUTF8ByteArray("BLS-SIG-KEYGEN-SALT-");

    /**
     * HKDF output length in bytes. Spec defines
     * {@code L = ceil((3 * ceil(log2(r))) / 16)}; for BLS12-381 r is 255 bits so
     * {@code L = ceil(765 / 16) = 48}.
     */
    private static final int L = 48;

    private BLS12_381BasicScheme()
    {
    }

    /**
     * Derive a secret key from input keying material per
     * draft-irtf-cfrg-bls-signature sec. 2.3.
     * <p>
     * Same {@code (ikm, keyInfo)} input always produces the same secret key,
     * so {@code ikm} should come from a high-entropy source the caller
     * controls (e.g. {@code SecureRandom.nextBytes}).
     *
     * @param ikm input keying material; the spec requires at least 32 bytes.
     * @param keyInfo optional context binding; pass an empty array if not used.
     * @return a secret key {@code 0 < sk < r}.
     */
    public static BigInteger keyGen(byte[] ikm, byte[] keyInfo)
    {
        if (ikm == null || ikm.length < 32)
        {
            throw new IllegalArgumentException("IKM must be at least 32 bytes");
        }
        if (keyInfo == null)
        {
            keyInfo = new byte[0];
        }

        byte[] ikmWithZero = Arrays.append(ikm, (byte)0x00);
        byte[] info = Arrays.append(keyInfo, (byte)((L >> 8) & 0xff));
        info = Arrays.append(info, (byte)(L & 0xff));

        byte[] salt = KEYGEN_SALT_INIT;
        BigInteger r = BLS12_381G1.ORDER;
        byte[] okm = new byte[L];

        try
        {
            // Loop on the negligible chance that OS2IP(OKM) mod r == 0.
            for (int iteration = 0; iteration < 16; ++iteration)
            {
                salt = sha256(salt);
                HKDFBytesGenerator hkdf = new HKDFBytesGenerator(SHA256Digest.newInstance());
                hkdf.init(new HKDFParameters(ikmWithZero, salt, info));
                hkdf.generateBytes(okm, 0, L);
                BigInteger sk = new BigInteger(1, okm).mod(r);
                if (sk.signum() != 0)
                {
                    return sk;
                }
            }
            throw new IllegalStateException("KeyGen failed to produce a non-zero secret key");
        }
        finally
        {
            Arrays.fill(okm, (byte)0);
            Arrays.fill(ikmWithZero, (byte)0);
        }
    }

    /**
     * Derive the public key for a given secret key: {@code PK = sk * G1_gen}.
     */
    public static ECPoint skToPk(BigInteger sk)
    {
        if (sk == null || sk.signum() <= 0 || sk.compareTo(BLS12_381G1.ORDER) >= 0)
        {
            throw new IllegalArgumentException("invalid secret key");
        }
        ECCurve curve = BLS12_381G1.createCurve();
        // Constant-time: sk is secret.
        return BLS12_381G1.constantTimeMultiply(BLS12_381G1.getGenerator(curve), sk);
    }

    /**
     * Validate a public key per draft-irtf-cfrg-bls-signature sec. 2.5:
     * non-identity, on the G1 curve, and in the prime-order subgroup.
     */
    public static boolean keyValidate(ECPoint pk)
    {
        if (pk == null || pk.isInfinity())
        {
            return false;
        }
        if (!pk.isValid())
        {
            return false;
        }
        return BLS12_381SubgroupCheck.isInG1Subgroup(pk);
    }

    /**
     * Sign a message under the BasicScheme: {@code sig = sk * H(message)}
     * where {@code H} is hash-to-G2 with the suite's DST.
     */
    public static BLS12_381G2Point sign(BigInteger sk, byte[] message)
    {
        if (sk == null || sk.signum() <= 0 || sk.compareTo(BLS12_381G1.ORDER) >= 0)
        {
            throw new IllegalArgumentException("invalid secret key");
        }
        BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(DST);
        BLS12_381G2Point q = h.hashToCurve(message);
        // Constant-time: sk is secret.
        return q.constantTimeMultiply(sk);
    }

    /**
     * Verify a BasicScheme signature. Returns {@code true} iff
     * {@code pk} is a valid G1 point in the prime-order subgroup,
     * {@code signature} is a valid G2 point in the prime-order subgroup,
     * and the pairing equation {@code e(G1_gen, sig) == e(pk, H(message))}
     * holds.
     */
    public static boolean verify(ECPoint pk, byte[] message, BLS12_381G2Point signature)
    {
        if (message == null)
        {
            throw new NullPointerException("message must not be null");
        }
        if (!keyValidate(pk))
        {
            return false;
        }
        if (signature == null || signature.isInfinity())
        {
            return false;
        }
        if (!BLS12_381SubgroupCheck.isInG2Subgroup(signature))
        {
            return false;
        }

        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g1 = BLS12_381G1.getGenerator(curve);
        BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(DST);
        BLS12_381G2Point q = h.hashToCurve(message);

        // Verify e(g1, sig) == e(pk, q) by checking the multi-pairing
        // e(g1, sig) * e(-pk, q) == 1. Combining the two Miller loops and
        // doing one final exponentiation halves the verify time vs. two
        // separate pair() calls.
        ECPoint negPk = pk.negate();
        Fp12Element acc = BLS12_381Pairing.multiPair(
            new ECPoint[]{g1, negPk},
            new BLS12_381G2Point[]{signature, q});
        return Fp12Element.ONE.equals(acc);
    }

    /**
     * Aggregate verification under the BasicScheme. Per
     * draft-irtf-cfrg-bls-signature sec. 3.1.1, the messages must all be
     * distinct — otherwise an attacker holding sk_1 and a victim public
     * key pk_2 can forge an aggregate by setting sig_1 = sk_1*H(m), sig_2
     * arbitrary such that sig_1 + sig_2 cancels into a known value. The
     * MessageAugmentation and ProofOfPossession suites avoid this
     * requirement structurally; this BasicScheme variant enforces it.
     */
    public static boolean aggregateVerify(ECPoint[] pks, byte[][] messages, BLS12_381G2Point sigAgg)
    {
        if (pks == null || messages == null || pks.length != messages.length || pks.length == 0)
        {
            return false;
        }
        for (int i = 0; i < messages.length; ++i)
        {
            if (pks[i] == null)
            {
                throw new NullPointerException("pks[" + i + "] must not be null");
            }
            if (messages[i] == null)
            {
                throw new NullPointerException("messages[" + i + "] must not be null");
            }
        }
        for (int i = 0; i < messages.length; ++i)
        {
            for (int j = i + 1; j < messages.length; ++j)
            {
                if (Arrays.areEqual(messages[i], messages[j]))
                {
                    return false;
                }
            }
        }
        BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(DST);
        BLS12_381G2Point[] hashes = new BLS12_381G2Point[pks.length];
        for (int i = 0; i < pks.length; ++i)
        {
            if (!keyValidate(pks[i]))
            {
                return false;
            }
            hashes[i] = h.hashToCurve(messages[i]);
        }
        return BLS12_381Aggregation.aggregateVerifyHashed(pks, hashes, sigAgg);
    }

    private static byte[] sha256(byte[] in)
    {
        Digest d = SHA256Digest.newInstance();
        d.update(in, 0, in.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }
}
