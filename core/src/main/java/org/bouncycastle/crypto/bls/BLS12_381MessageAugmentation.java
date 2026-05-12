package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * BLS signatures MessageAugmentation suite over BLS12-381, per
 * draft-irtf-cfrg-bls-signature: signature suite
 * {@code BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_}.
 * <p>
 * Differs from {@link BLS12_381BasicScheme} by prepending the public-key
 * encoding to the message before hashing. The augmentation defends against
 * rogue-key attacks in aggregate-verification without the standalone
 * proof-of-possession step that {@link BLS12_381ProofOfPossession} requires.
 * <p>
 * The public-key prefix used in the hash-to-curve input is the
 * Zcash-format 48-byte compressed G1 encoding produced by
 * {@link BLS12_381Serialization#compressG1}, matching
 * draft-irtf-cfrg-bls-signature's {@code point_to_pubkey} so signatures are
 * potentially interoperable with other BLS implementations once verified
 * against published test vectors.
 */
public class BLS12_381MessageAugmentation
{
    public static final byte[] DST = Strings.toUTF8ByteArray(
        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_");

    private BLS12_381MessageAugmentation()
    {
    }

    /**
     * Sign under the MessageAugmentation suite:
     * {@code sig = sk * H(SkToPk(sk) || message)} with the AUG DST.
     */
    public static BLS12_381G2Point sign(BigInteger sk, byte[] message)
    {
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        byte[] augmented = augment(pk, message);
        BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(DST);
        // Constant-time: sk is secret.
        return h.hashToCurve(augmented).constantTimeMultiply(sk);
    }

    /**
     * Verify under the MessageAugmentation suite. Returns {@code true} iff
     * {@code pk} is a valid prime-order G1 point, {@code signature} is a
     * valid prime-order G2 point, and the pairing equation
     * {@code e(G1_gen, sig) == e(pk, H(pk || message))} holds.
     */
    public static boolean verify(ECPoint pk, byte[] message, BLS12_381G2Point signature)
    {
        if (message == null)
        {
            throw new NullPointerException("message must not be null");
        }
        if (!BLS12_381BasicScheme.keyValidate(pk))
        {
            return false;
        }
        if (signature == null || signature.isInfinity()
            || !BLS12_381SubgroupCheck.isInG2Subgroup(signature))
        {
            return false;
        }

        byte[] augmented = augment(pk, message);
        BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(DST);
        BLS12_381G2Point q = h.hashToCurve(augmented);

        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g1 = BLS12_381G1.getGenerator(curve);

        Fp12Element acc = BLS12_381Pairing.multiPair(
            new ECPoint[]{g1, pk.negate()},
            new BLS12_381G2Point[]{signature, q});
        return Fp12Element.ONE.equals(acc);
    }

    /**
     * Aggregate verification under the MessageAugmentation suite. Distinct
     * messages are not required: the augmentation makes each
     * {@code H(pk_i || msg_i)} input unique even when the {@code msg_i} repeat.
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
        BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(DST);
        BLS12_381G2Point[] hashes = new BLS12_381G2Point[pks.length];
        for (int i = 0; i < pks.length; ++i)
        {
            if (!BLS12_381BasicScheme.keyValidate(pks[i]))
            {
                return false;
            }
            hashes[i] = h.hashToCurve(augment(pks[i], messages[i]));
        }
        return BLS12_381Aggregation.aggregateVerifyHashed(pks, hashes, sigAgg);
    }

    /**
     * Build {@code SkToPk(sk) || message} using the Zcash-format 48-byte
     * compressed G1 encoding for the public-key prefix.
     */
    static byte[] augment(ECPoint pk, byte[] message)
    {
        byte[] pkBytes = BLS12_381Serialization.compressG1(pk);
        return Arrays.concatenate(pkBytes, message);
    }
}
