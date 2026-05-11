package org.bouncycastle.crypto.bls;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Helper for aggregating BLS12-381 signatures and verifying aggregates.
 * <p>
 * Aggregation itself is suite-independent — it is just point addition in
 * G2. The aggregate-verify equation
 * {@code e(G1_gen, sig_agg) == prod_i e(pk_i, H(msg_i))}
 * collapses to a single multi-pairing check
 * {@code multiPair([(-G1_gen, sig_agg), (pk_1, H_1), ...]) == 1},
 * which is one final exponentiation regardless of how many signers
 * participated. Each suite computes its own list of hashed-message G2
 * points and then defers to {@link #aggregateVerifyHashed}.
 */
public class BLS12_381Aggregation
{
    private BLS12_381Aggregation()
    {
    }

    /**
     * Aggregate a list of BLS signatures by summing them in G2.
     *
     * @param signatures one or more BLS signatures (G2 points). Must be non-empty.
     * @return {@code sig_1 + sig_2 + ... + sig_n}.
     */
    public static BLS12_381G2Point aggregate(BLS12_381G2Point[] signatures)
    {
        if (signatures == null || signatures.length == 0)
        {
            throw new IllegalArgumentException("signatures must be non-empty");
        }
        BLS12_381G2Point agg = signatures[0];
        for (int i = 1; i < signatures.length; ++i)
        {
            agg = agg.add(signatures[i]);
        }
        return agg;
    }

    /**
     * Aggregate-verify with already-computed hashed-message G2 points. Each
     * BLS signature suite preprocesses its messages differently
     * (BasicScheme: just msg; MessageAugmentation: pk||msg; ProofOfPossession:
     * just msg with POP DST) and supplies the resulting hashes here.
     * <p>
     * Verifies {@code multiPair([(-G1_gen, sig_agg), (pk_0, hashes_0),
     * ..., (pk_{n-1}, hashes_{n-1})]) == 1}.
     *
     * @param pks the signer public keys; assumed already validated by the caller.
     * @param hashedMsgs the H(msg_i) G2 points, one per signer.
     * @param sigAgg the aggregate signature.
     * @return {@code true} iff the aggregate verifies.
     */
    static boolean aggregateVerifyHashed(ECPoint[] pks, BLS12_381G2Point[] hashedMsgs, BLS12_381G2Point sigAgg)
    {
        if (sigAgg == null || sigAgg.isInfinity())
        {
            return false;
        }
        if (!BLS12_381SubgroupCheck.isInG2Subgroup(sigAgg))
        {
            return false;
        }
        if (pks.length != hashedMsgs.length || pks.length == 0)
        {
            return false;
        }

        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint negG1 = BLS12_381G1.getGenerator(curve).negate();

        ECPoint[] g1 = new ECPoint[pks.length + 1];
        BLS12_381G2Point[] g2 = new BLS12_381G2Point[pks.length + 1];

        g1[0] = negG1;
        g2[0] = sigAgg;
        for (int i = 0; i < pks.length; ++i)
        {
            g1[i + 1] = pks[i];
            g2[i + 1] = hashedMsgs[i];
        }

        return Fp12Element.ONE.equals(BLS12_381Pairing.multiPair(g1, g2));
    }
}
