package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381Aggregation;
import org.bouncycastle.crypto.bls.BLS12_381BasicScheme;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.crypto.bls.BLS12_381MessageAugmentation;
import org.bouncycastle.crypto.bls.BLS12_381ProofOfPossession;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;

/**
 * Functional tests for the MessageAugmentation and ProofOfPossession BLS
 * suites and for aggregate verification (across all three suites).
 */
public class BLS12_381SuitesTest
    extends TestCase
{
    private static byte[] ikm32(int seed)
    {
        byte[] ikm = new byte[32];
        for (int i = 0; i < ikm.length; ++i)
        {
            ikm[i] = (byte)((i + 1) * (seed + 7));
        }
        return ikm;
    }

    public void testAugRoundTrip()
    {
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(1), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        byte[] msg = Strings.toUTF8ByteArray("AUG round-trip");
        BLS12_381G2Point sig = BLS12_381MessageAugmentation.sign(sk, msg);
        assertTrue(BLS12_381MessageAugmentation.verify(pk, msg, sig));
    }

    public void testAugIsBoundToPublicKey()
    {
        // Sign a message with sk_1, verify with the matching pk_1.
        BigInteger sk1 = BLS12_381BasicScheme.keyGen(ikm32(2), new byte[0]);
        ECPoint pk1 = BLS12_381BasicScheme.skToPk(sk1);
        byte[] msg = Strings.toUTF8ByteArray("hello");
        BLS12_381G2Point sig = BLS12_381MessageAugmentation.sign(sk1, msg);
        assertTrue(BLS12_381MessageAugmentation.verify(pk1, msg, sig));

        // The same signature should NOT verify under a different public key,
        // because the augmented hash includes pk in the input.
        BigInteger sk2 = BLS12_381BasicScheme.keyGen(ikm32(3), new byte[0]);
        ECPoint pk2 = BLS12_381BasicScheme.skToPk(sk2);
        assertFalse(BLS12_381MessageAugmentation.verify(pk2, msg, sig));
    }

    public void testAugIsDifferentFromBasicScheme()
    {
        // A BasicScheme signature should NOT verify under MessageAugmentation
        // (different DST + different hash input).
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(4), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        byte[] msg = Strings.toUTF8ByteArray("cross-suite");
        BLS12_381G2Point basicSig = BLS12_381BasicScheme.sign(sk, msg);
        assertFalse("basic sig must not verify under AUG suite",
            BLS12_381MessageAugmentation.verify(pk, msg, basicSig));
    }

    public void testPopRoundTrip()
    {
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(5), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        byte[] msg = Strings.toUTF8ByteArray("POP round-trip");
        BLS12_381G2Point sig = BLS12_381ProofOfPossession.sign(sk, msg);
        assertTrue(BLS12_381ProofOfPossession.verify(pk, msg, sig));
    }

    public void testPopProveAndVerify()
    {
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(6), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        BLS12_381G2Point pop = BLS12_381ProofOfPossession.popProve(sk);
        assertTrue("PopProve output must verify under matching pk",
            BLS12_381ProofOfPossession.popVerify(pk, pop));
    }

    public void testPopRejectsForWrongKey()
    {
        BigInteger sk1 = BLS12_381BasicScheme.keyGen(ikm32(7), new byte[0]);
        BigInteger sk2 = BLS12_381BasicScheme.keyGen(ikm32(8), new byte[0]);
        ECPoint pk2 = BLS12_381BasicScheme.skToPk(sk2);
        BLS12_381G2Point pop1 = BLS12_381ProofOfPossession.popProve(sk1);
        assertFalse("PopProve(sk_1) must not verify under pk_2",
            BLS12_381ProofOfPossession.popVerify(pk2, pop1));
    }

    public void testBasicAggregateRoundTrip()
    {
        BigInteger sk1 = BLS12_381BasicScheme.keyGen(ikm32(9), new byte[0]);
        BigInteger sk2 = BLS12_381BasicScheme.keyGen(ikm32(10), new byte[0]);
        ECPoint pk1 = BLS12_381BasicScheme.skToPk(sk1);
        ECPoint pk2 = BLS12_381BasicScheme.skToPk(sk2);
        byte[] m1 = Strings.toUTF8ByteArray("agg-msg-1");
        byte[] m2 = Strings.toUTF8ByteArray("agg-msg-2");

        BLS12_381G2Point sig1 = BLS12_381BasicScheme.sign(sk1, m1);
        BLS12_381G2Point sig2 = BLS12_381BasicScheme.sign(sk2, m2);
        BLS12_381G2Point agg = BLS12_381Aggregation.aggregate(
            new BLS12_381G2Point[]{sig1, sig2});

        assertTrue(BLS12_381BasicScheme.aggregateVerify(
            new ECPoint[]{pk1, pk2}, new byte[][]{m1, m2}, agg));
    }

    public void testBasicAggregateRejectsRepeatedMessages()
    {
        // BasicScheme requires distinct messages for aggregate verify. Even a
        // genuinely correct aggregate signature over duplicated messages must
        // be rejected by aggregateVerify per draft-irtf-cfrg-bls-signature
        // sec. 3.1.1.
        BigInteger sk1 = BLS12_381BasicScheme.keyGen(ikm32(11), new byte[0]);
        BigInteger sk2 = BLS12_381BasicScheme.keyGen(ikm32(12), new byte[0]);
        ECPoint pk1 = BLS12_381BasicScheme.skToPk(sk1);
        ECPoint pk2 = BLS12_381BasicScheme.skToPk(sk2);
        byte[] msg = Strings.toUTF8ByteArray("same-msg");

        BLS12_381G2Point sig1 = BLS12_381BasicScheme.sign(sk1, msg);
        BLS12_381G2Point sig2 = BLS12_381BasicScheme.sign(sk2, msg);
        BLS12_381G2Point agg = BLS12_381Aggregation.aggregate(
            new BLS12_381G2Point[]{sig1, sig2});

        assertFalse("BasicScheme aggregateVerify must reject repeated messages",
            BLS12_381BasicScheme.aggregateVerify(
                new ECPoint[]{pk1, pk2}, new byte[][]{msg, msg}, agg));
    }

    public void testAugAggregateAcceptsRepeatedMessages()
    {
        // Augmented hash inputs (pk_i || msg) make duplicate-msg aggregates
        // safe under MessageAugmentation.
        BigInteger sk1 = BLS12_381BasicScheme.keyGen(ikm32(13), new byte[0]);
        BigInteger sk2 = BLS12_381BasicScheme.keyGen(ikm32(14), new byte[0]);
        ECPoint pk1 = BLS12_381BasicScheme.skToPk(sk1);
        ECPoint pk2 = BLS12_381BasicScheme.skToPk(sk2);
        byte[] msg = Strings.toUTF8ByteArray("agg-aug-same-msg");

        BLS12_381G2Point sig1 = BLS12_381MessageAugmentation.sign(sk1, msg);
        BLS12_381G2Point sig2 = BLS12_381MessageAugmentation.sign(sk2, msg);
        BLS12_381G2Point agg = BLS12_381Aggregation.aggregate(
            new BLS12_381G2Point[]{sig1, sig2});

        assertTrue(BLS12_381MessageAugmentation.aggregateVerify(
            new ECPoint[]{pk1, pk2}, new byte[][]{msg, msg}, agg));
    }

    public void testFastAggregateVerify()
    {
        // ProofOfPossession FastAggregateVerify: same message, multiple signers,
        // single pairing check on the aggregated public key.
        BigInteger sk1 = BLS12_381BasicScheme.keyGen(ikm32(15), new byte[0]);
        BigInteger sk2 = BLS12_381BasicScheme.keyGen(ikm32(16), new byte[0]);
        BigInteger sk3 = BLS12_381BasicScheme.keyGen(ikm32(17), new byte[0]);
        ECPoint pk1 = BLS12_381BasicScheme.skToPk(sk1);
        ECPoint pk2 = BLS12_381BasicScheme.skToPk(sk2);
        ECPoint pk3 = BLS12_381BasicScheme.skToPk(sk3);
        byte[] msg = Strings.toUTF8ByteArray("fast-agg-same-msg");

        BLS12_381G2Point sig1 = BLS12_381ProofOfPossession.sign(sk1, msg);
        BLS12_381G2Point sig2 = BLS12_381ProofOfPossession.sign(sk2, msg);
        BLS12_381G2Point sig3 = BLS12_381ProofOfPossession.sign(sk3, msg);
        BLS12_381G2Point agg = BLS12_381Aggregation.aggregate(
            new BLS12_381G2Point[]{sig1, sig2, sig3});

        assertTrue(BLS12_381ProofOfPossession.fastAggregateVerify(
            new ECPoint[]{pk1, pk2, pk3}, msg, agg));
    }

    public void testFastAggregateVerifyRejectsTamperedSignature()
    {
        BigInteger sk1 = BLS12_381BasicScheme.keyGen(ikm32(18), new byte[0]);
        BigInteger sk2 = BLS12_381BasicScheme.keyGen(ikm32(19), new byte[0]);
        ECPoint pk1 = BLS12_381BasicScheme.skToPk(sk1);
        ECPoint pk2 = BLS12_381BasicScheme.skToPk(sk2);
        byte[] msg = Strings.toUTF8ByteArray("tamper");

        BLS12_381G2Point sig1 = BLS12_381ProofOfPossession.sign(sk1, msg);
        BLS12_381G2Point sig2 = BLS12_381ProofOfPossession.sign(sk2, msg);
        BLS12_381G2Point agg = BLS12_381Aggregation.aggregate(
            new BLS12_381G2Point[]{sig1, sig2})
            .add(org.bouncycastle.crypto.bls.BLS12_381G2.getGenerator());

        assertFalse(BLS12_381ProofOfPossession.fastAggregateVerify(
            new ECPoint[]{pk1, pk2}, msg, agg));
    }

    public void testAggregateVerifyRejectsWrongOrder()
    {
        // Aggregate signature was generated with messages {m1, m2}, but
        // verification tries {m2, m1}. The pairs (pk_i, msg_i) get scrambled,
        // so verify must reject.
        BigInteger sk1 = BLS12_381BasicScheme.keyGen(ikm32(20), new byte[0]);
        BigInteger sk2 = BLS12_381BasicScheme.keyGen(ikm32(21), new byte[0]);
        ECPoint pk1 = BLS12_381BasicScheme.skToPk(sk1);
        ECPoint pk2 = BLS12_381BasicScheme.skToPk(sk2);
        byte[] m1 = Strings.toUTF8ByteArray("ordered-1");
        byte[] m2 = Strings.toUTF8ByteArray("ordered-2");

        BLS12_381G2Point sig1 = BLS12_381BasicScheme.sign(sk1, m1);
        BLS12_381G2Point sig2 = BLS12_381BasicScheme.sign(sk2, m2);
        BLS12_381G2Point agg = BLS12_381Aggregation.aggregate(
            new BLS12_381G2Point[]{sig1, sig2});

        // Swapped: pk1 with m2, pk2 with m1.
        assertFalse(BLS12_381BasicScheme.aggregateVerify(
            new ECPoint[]{pk1, pk2}, new byte[][]{m2, m1}, agg));
    }

    // ---------------------------------------------------------------------
    // BLS12_381Aggregation.aggregate error paths (review gap G5).
    // ---------------------------------------------------------------------

    public void testAggregateRejectsNull()
    {
        try
        {
            BLS12_381Aggregation.aggregate(null);
            fail("aggregate(null) should throw");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testAggregateRejectsEmpty()
    {
        try
        {
            BLS12_381Aggregation.aggregate(new BLS12_381G2Point[0]);
            fail("aggregate of zero signatures should throw");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testAggregateSingleSigner()
    {
        // Single-element aggregate must equal the input — point addition
        // with no second operand is the identity case.
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(30), new byte[0]);
        BLS12_381G2Point sig = BLS12_381BasicScheme.sign(sk,
            Strings.toUTF8ByteArray("single-signer"));
        BLS12_381G2Point agg = BLS12_381Aggregation.aggregate(
            new BLS12_381G2Point[]{sig});
        assertEquals("aggregate of one signature must equal that signature",
            sig, agg);
    }

    // ---------------------------------------------------------------------
    // aggregateVerify argument-shape validation (review gap G6).
    // The four guard branches in each scheme's aggregateVerify (null pks,
    // null msgs, length mismatch, empty input) all return false rather
    // than throwing — pin each one.
    // ---------------------------------------------------------------------

    public void testAggregateVerifyRejectsNullPks()
    {
        byte[] msg = Strings.toUTF8ByteArray("x");
        BLS12_381G2Point dummy = BLS12_381G2Point.INFINITY;
        assertFalse(BLS12_381BasicScheme.aggregateVerify(
            null, new byte[][]{msg}, dummy));
    }

    public void testAggregateVerifyRejectsNullMessages()
    {
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(31), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        BLS12_381G2Point dummy = BLS12_381G2Point.INFINITY;
        assertFalse(BLS12_381BasicScheme.aggregateVerify(
            new ECPoint[]{pk}, null, dummy));
    }

    public void testAggregateVerifyRejectsLengthMismatch()
    {
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(32), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        BLS12_381G2Point dummy = BLS12_381G2Point.INFINITY;
        assertFalse("pks.length != messages.length must return false",
            BLS12_381BasicScheme.aggregateVerify(
                new ECPoint[]{pk}, new byte[][]{}, dummy));
    }

    public void testAggregateVerifyRejectsEmpty()
    {
        BLS12_381G2Point dummy = BLS12_381G2Point.INFINITY;
        assertFalse("empty pks/messages must return false",
            BLS12_381BasicScheme.aggregateVerify(
                new ECPoint[0], new byte[0][], dummy));
    }

    // ---------------------------------------------------------------------
    // PoP DST cross-domain rejection (review gap G7).
    //
    // The PoP suite uses two distinct DSTs: the signing DST
    // BLS_SIG_..._POP_ and the proof-of-possession DST BLS_POP_..._POP_.
    // A regular signature produced under the signing DST — even one
    // whose message bytes happen to equal compress(pk) — must NOT verify
    // as a proof of possession. If the two DSTs ever got aliased, this
    // test would catch it.
    // ---------------------------------------------------------------------

    public void testPopVerifyRejectsRegularSignatureOverPkBytes()
    {
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(33), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        byte[] pkBytes = org.bouncycastle.crypto.bls.BLS12_381Serialization.compressG1(pk);

        // Sign compress(pk) using the SIG/POP_ DST (regular sign path, not popProve).
        BLS12_381G2Point sigOverPkBytes = BLS12_381ProofOfPossession.sign(sk, pkBytes);

        // This signature lives under the SIG DST, not the POP DST. popVerify
        // must reject it even though the message bytes match what popProve
        // would hash.
        assertFalse("regular sign output must not verify as a PoP proof",
            BLS12_381ProofOfPossession.popVerify(pk, sigOverPkBytes));
    }

    // ---------------------------------------------------------------------
    // Large-N aggregate smoke test (review gap G17).
    //
    // Surfaces accidental O(n^2) regressions in the message-grouping
    // path that was added for B1, plus stress-tests multiPair on a
    // larger-than-trivial input list.
    // ---------------------------------------------------------------------

    public void testBasicAggregateVerifyManySigners()
    {
        int n = 50;
        BigInteger[] sks = new BigInteger[n];
        ECPoint[] pks = new ECPoint[n];
        byte[][] msgs = new byte[n][];
        BLS12_381G2Point[] sigs = new BLS12_381G2Point[n];
        for (int i = 0; i < n; ++i)
        {
            sks[i] = BLS12_381BasicScheme.keyGen(ikm32(100 + i), new byte[0]);
            pks[i] = BLS12_381BasicScheme.skToPk(sks[i]);
            msgs[i] = Strings.toUTF8ByteArray("large-agg-msg-" + i);
            sigs[i] = BLS12_381BasicScheme.sign(sks[i], msgs[i]);
        }
        BLS12_381G2Point agg = BLS12_381Aggregation.aggregate(sigs);
        assertTrue("50-signer distinct-message aggregate must verify",
            BLS12_381BasicScheme.aggregateVerify(pks, msgs, agg));
    }

    public void testPopAggregateVerifyRejectsCancelingKeysOnSharedMessage()
    {
        // draft-irtf-cfrg-bls-signature sec. 2.9 (CoreAggregateVerify) lines
        // 12-13 require that when multiple PKs are aggregated for the same
        // effective message, the aggregate RK_i MUST pass KeyValidate.
        //
        // Scenario this protects against: an attacker registers two keys
        // (pk1, pk2) where pk2 = -pk1, both with valid PoP proofs (sk2 = r -
        // sk1 produces a valid signing key; PopProve over each succeeds
        // independently). Under the PoP suite's aggregateVerify, which does
        // NOT require distinct messages, the attacker submits an aggregate
        // claiming (pk1, pk2, victim_pk) signed (m, m, m_v). In a flat
        // multi-pairing the pk1+pk2 row sums to identity, the m
        // contributions cancel, and the equation reduces to a plain
        // single-signer check of victim_pk over m_v — which verifies even
        // though the aggregate isn't faithfully attributable to pk1, pk2
        // for message m. The spec's grouping + RK_i KeyValidate step
        // rejects this; this test asserts BC does too.
        BigInteger sk1 = BLS12_381BasicScheme.keyGen(ikm32(40), new byte[0]);
        BigInteger sk2 = BLS12_381G1.ORDER.subtract(sk1);  // pk2 = -pk1
        BigInteger sk3 = BLS12_381BasicScheme.keyGen(ikm32(41), new byte[0]);
        ECPoint pk1 = BLS12_381BasicScheme.skToPk(sk1);
        ECPoint pk2 = BLS12_381BasicScheme.skToPk(sk2);
        ECPoint pk3 = BLS12_381BasicScheme.skToPk(sk3);

        // Sanity-check the construction: each pk passes KeyValidate (and
        // therefore would pass popVerify with a real PoP), but pk1+pk2 is
        // the identity.
        assertTrue("pk1 should be a validly-shaped public key",
            BLS12_381BasicScheme.keyValidate(pk1));
        assertTrue("pk2 should be a validly-shaped public key",
            BLS12_381BasicScheme.keyValidate(pk2));
        assertTrue("by construction, pk1 + pk2 must be the identity",
            pk1.add(pk2).normalize().isInfinity());

        byte[] m = Strings.toUTF8ByteArray("canceling-message");
        byte[] mv = Strings.toUTF8ByteArray("victim-message");

        BLS12_381G2Point sig1 = BLS12_381ProofOfPossession.sign(sk1, m);
        BLS12_381G2Point sig2 = BLS12_381ProofOfPossession.sign(sk2, m);
        BLS12_381G2Point sig3 = BLS12_381ProofOfPossession.sign(sk3, mv);
        BLS12_381G2Point agg = BLS12_381Aggregation.aggregate(
            new BLS12_381G2Point[]{sig1, sig2, sig3});

        assertFalse("PoP aggregateVerify must reject aggregates where two "
            + "PKs signing the same message sum to the identity "
            + "(draft-irtf-cfrg-bls-signature sec. 2.9 line 13)",
            BLS12_381ProofOfPossession.aggregateVerify(
                new ECPoint[]{pk1, pk2, pk3},
                new byte[][]{m, m, mv},
                agg));
    }
}
