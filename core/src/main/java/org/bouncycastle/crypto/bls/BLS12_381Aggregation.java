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
 * {@code multiPair([(-G1_gen, sig_agg), (RK_1, H_1), ...]) == 1},
 * where each {@code H_i} is a distinct hashed-message G2 point and
 * {@code RK_i} is the sum of all public keys that signed the corresponding
 * message — the "QK_set" aggregation from
 * draft-irtf-cfrg-bls-signature sec. 2.9. Each suite computes its own list
 * of hashed-message G2 points (BasicScheme: H(msg) with NUL DST;
 * MessageAugmentation: H(pk || msg) with AUG DST; ProofOfPossession:
 * H(msg) with POP DST) and then defers to {@link #aggregateVerifyHashed},
 * which performs the message-grouping plus a single final exponentiation
 * regardless of how many signers participated.
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
        for (int i = 0; i < signatures.length; ++i)
        {
            if (signatures[i] == null)
            {
                throw new IllegalArgumentException("signatures must not contain null");
            }
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
     * Implements draft-irtf-cfrg-bls-signature sec. 2.9 (CoreAggregateVerify),
     * which requires inputs sharing an effective message to have their PKs
     * aggregated into a single {@code RK_i} before pairing, and the aggregate
     * to be {@link BLS12_381BasicScheme#keyValidate validated} (lines 12-13)
     * when more than one PK contributed. See
     * {@link #groupAndCheckIdentity} for the rationale.
     * <p>
     * Verifies {@code multiPair([(-G1_gen, sig_agg), (RK_1, H_1), ...,
     * (RK_l, H_l)]) == 1} where {@code H_i} ranges over the distinct
     * hashed-message G2 points.
     *
     * @param pks the signer public keys; assumed already validated by the
     *            caller (per-input {@code KeyValidate} per spec lines 7-9).
     *            This method handles the additional spec line 13 check on
     *            the aggregate {@code RK_i}.
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

        // Group inputs by hashed-message and validate each multi-PK aggregate.
        // Returns null (=> verify INVALID) on the spec line 13 violation;
        // returns the grouped (RK_i, H_i) lists otherwise.
        Object[] grouped = groupAndCheckIdentity(pks, hashedMsgs);
        if (grouped == null)
        {
            return false;
        }
        ECPoint[] groupedPks = (ECPoint[])grouped[0];
        BLS12_381G2Point[] groupedHashes = (BLS12_381G2Point[])grouped[1];

        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint negG1 = BLS12_381G1.getGenerator(curve).negate();

        ECPoint[] g1 = new ECPoint[groupedPks.length + 1];
        BLS12_381G2Point[] g2 = new BLS12_381G2Point[groupedPks.length + 1];

        g1[0] = negG1;
        g2[0] = sigAgg;
        for (int i = 0; i < groupedPks.length; ++i)
        {
            g1[i + 1] = groupedPks[i];
            g2[i + 1] = groupedHashes[i];
        }

        return Fp12Element.ONE.equals(BLS12_381Pairing.multiPair(g1, g2));
    }

    /**
     * Group {@code (pks, hashedMsgs)} pairs by hashed-message and apply the
     * draft-irtf-cfrg-bls-signature sec. 2.9 line 13 check.
     * <p>
     * Two messages are equal iff their hash-to-curve outputs are equal
     * (hash-to-curve is deterministic with a fixed DST), so grouping by
     * {@link BLS12_381G2Point#equals(Object) hashedMsg} is equivalent to
     * the spec's grouping by raw message {@code m_i}.
     * <p>
     * <b>Why this exists.</b> Skipping the grouping would let an attacker
     * who controls a key pair {@code (sk_a, sk_b)} with {@code sk_b = r -
     * sk_a} (so {@code pk_b = -pk_a}) register both with valid
     * {@link BLS12_381ProofOfPossession#popVerify PoP proofs} — each
     * popVerify checks the individual key, which is sound. The attacker
     * then submits an aggregate over messages {@code (m, m, m_v)} from
     * {@code (pk_a, pk_b, pk_v)}: in a flat multi-pairing the {@code m}-row
     * contributions {@code e(pk_a, H(m)) * e(pk_b, H(m)) = e(pk_a + pk_b,
     * H(m)) = e(O, H(m)) = 1} cancel, and the equation reduces to a plain
     * single-signer check of {@code pk_v} over {@code m_v} — which
     * verifies, even though the aggregate isn't faithfully attributable to
     * {@code pk_a, pk_b} for message {@code m}. The spec's grouping +
     * non-identity check on {@code RK_i = pk_a + pk_b} catches this.
     * <p>
     * For BasicScheme this is structurally moot: that suite's
     * {@code aggregateVerify} rejects repeated messages upstream, so each
     * group has size 1 here. For MessageAugmentation, the augmented
     * messages {@code pk_i || msg_i} differ whenever the {@code pk_i}
     * differ, so size-{@literal >}1 groups only arise from duplicate
     * {@code (pk, msg)} rows where the aggregate {@code k * pk} is
     * non-identity for any valid {@code pk}. The check is load-bearing
     * for ProofOfPossession's {@code aggregateVerify} specifically.
     * <p>
     * KeyValidate on an aggregate of subgroup elements reduces to a
     * non-identity check: subgroup membership is preserved by addition,
     * and each input PK has already been validated by the calling scheme.
     *
     * @return a length-2 array {@code [ECPoint[] groupedPks,
     *         BLS12_381G2Point[] groupedHashes]} on success; {@code null}
     *         if any size-{@literal >}1 group aggregates to the identity.
     */
    private static Object[] groupAndCheckIdentity(ECPoint[] pks, BLS12_381G2Point[] hashedMsgs)
    {
        int n = pks.length;
        BLS12_381G2Point[] groupHashes = new BLS12_381G2Point[n];
        ECPoint[] groupPkSums = new ECPoint[n];
        // Tracks |QK_set_i| > 1 to gate the spec line 12 conditional —
        // single-signer groups are never identity for any valid input PK,
        // so we only check the aggregate when something was added in.
        boolean[] groupHasMultiple = new boolean[n];
        int numGroups = 0;

        // O(n^2) linear-scan grouping. Cheap in practice because
        // BLS12_381G2Point.equals is a pair of Fp^2 BigInteger compares
        // and typical aggregate sizes are small; a hash-based map could be
        // substituted later if profiling shows this matters.
        for (int i = 0; i < n; ++i)
        {
            int existing = -1;
            for (int j = 0; j < numGroups; ++j)
            {
                if (groupHashes[j].equals(hashedMsgs[i]))
                {
                    existing = j;
                    break;
                }
            }
            if (existing < 0)
            {
                groupHashes[numGroups] = hashedMsgs[i];
                groupPkSums[numGroups] = pks[i];
                numGroups++;
            }
            else
            {
                groupPkSums[existing] = groupPkSums[existing].add(pks[i]);
                groupHasMultiple[existing] = true;
            }
        }

        for (int i = 0; i < numGroups; ++i)
        {
            if (groupHasMultiple[i] && groupPkSums[i].normalize().isInfinity())
            {
                return null;
            }
        }

        // Trim to actual group count for the caller's multi-pairing array build.
        ECPoint[] trimmedPks = new ECPoint[numGroups];
        BLS12_381G2Point[] trimmedHashes = new BLS12_381G2Point[numGroups];
        System.arraycopy(groupPkSums, 0, trimmedPks, 0, numGroups);
        System.arraycopy(groupHashes, 0, trimmedHashes, 0, numGroups);
        return new Object[]{trimmedPks, trimmedHashes};
    }
}
