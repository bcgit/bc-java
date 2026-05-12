package org.bouncycastle.crypto.bls;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;

/**
 * BLS signatures ProofOfPossession suite over BLS12-381, per
 * draft-irtf-cfrg-bls-signature: signature suite
 * {@code BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_} together with a
 * separate proof-of-possession message that uses the
 * {@code BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_} DST.
 * <p>
 * This suite is the only one that supports {@link #fastAggregateVerify} —
 * all signers signed the same message, so verification reduces to summing
 * the public keys and running a single pairing check. The standalone
 * {@link #popProve}/{@link #popVerify} primitives let a registry verifier
 * confirm that a signer holds the secret key for their declared public key
 * before accepting their signatures into an aggregate.
 * <p>
 * The public-key bytes used in the {@link #popProve}/{@link #popVerify}
 * hash input are the Zcash-format 48-byte compressed G1 encoding produced
 * by {@link BLS12_381Serialization#compressG1}, matching
 * draft-irtf-cfrg-bls-signature's {@code point_to_pubkey}.
 */
public class BLS12_381ProofOfPossession
{
    public static final byte[] DST = Strings.toUTF8ByteArray(
        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");

    public static final byte[] POP_DST = Strings.toUTF8ByteArray(
        "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");

    private BLS12_381ProofOfPossession()
    {
    }

    public static BLS12_381G2Point sign(BigInteger sk, byte[] message)
    {
        if (sk == null || sk.signum() <= 0 || sk.compareTo(BLS12_381G1.ORDER) >= 0)
        {
            throw new IllegalArgumentException("invalid secret key");
        }
        BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(DST);
        // Constant-time: sk is secret.
        return h.hashToCurve(message).constantTimeMultiply(sk);
    }

    public static boolean verify(ECPoint pk, byte[] message, BLS12_381G2Point signature)
    {
        return verifyImpl(DST, pk, message, signature);
    }

    /**
     * Generate a proof-of-possession for {@code sk}. The proof is bound to
     * {@code SkToPk(sk)} via the POP DST and the public-key encoding so a
     * verifier can confirm the signer holds the matching secret key without
     * any context message.
     */
    public static BLS12_381G2Point popProve(BigInteger sk)
    {
        // skToPk validates sk for us — it throws on sk <= 0 or sk >= r.
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        byte[] pkBytes = BLS12_381Serialization.compressG1(pk);
        BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(POP_DST);
        // Constant-time: sk is secret.
        return h.hashToCurve(pkBytes).constantTimeMultiply(sk);
    }

    /**
     * Verify a proof-of-possession against the declared public key.
     */
    public static boolean popVerify(ECPoint pk, BLS12_381G2Point proof)
    {
        if (!BLS12_381BasicScheme.keyValidate(pk))
        {
            return false;
        }
        byte[] pkBytes = BLS12_381Serialization.compressG1(pk);
        return verifyImpl(POP_DST, pk, pkBytes, proof);
    }

    /**
     * Aggregate verification under the ProofOfPossession suite. Distinct
     * messages are not required because the standalone PoP step is expected
     * to have screened out rogue keys before any aggregation is attempted.
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
            hashes[i] = h.hashToCurve(messages[i]);
        }
        return BLS12_381Aggregation.aggregateVerifyHashed(pks, hashes, sigAgg);
    }

    /**
     * Fast aggregate verification: every signer signed the same message,
     * so {@code e(G1, sig_agg) == e(sum(pk_i), H(message))} reduces to a
     * single pairing check on the aggregated public key. Caller is
     * expected to have run {@link #popVerify} on each {@code pk_i} before
     * trusting the aggregate.
     */
    public static boolean fastAggregateVerify(ECPoint[] pks, byte[] message, BLS12_381G2Point sigAgg)
    {
        if (pks == null || pks.length == 0)
        {
            return false;
        }
        ECPoint pkAgg = pks[0];
        for (int i = 0; i < pks.length; ++i)
        {
            if (!BLS12_381BasicScheme.keyValidate(pks[i]))
            {
                return false;
            }
            if (i > 0)
            {
                pkAgg = pkAgg.add(pks[i]);
            }
        }
        pkAgg = pkAgg.normalize();
        if (pkAgg.isInfinity())
        {
            return false;
        }
        return verifyImpl(DST, pkAgg, message, sigAgg);
    }

    private static boolean verifyImpl(byte[] dst, ECPoint pk, byte[] message, BLS12_381G2Point signature)
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
        BLS12_381G2HashToCurve h = new BLS12_381G2HashToCurve(dst);
        BLS12_381G2Point q = h.hashToCurve(message);
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g1 = BLS12_381G1.getGenerator(curve);
        Fp12Element acc = BLS12_381Pairing.multiPair(
            new ECPoint[]{g1, pk.negate()},
            new BLS12_381G2Point[]{signature, q});
        return Fp12Element.ONE.equals(acc);
    }
}
