package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381Aggregation;
import org.bouncycastle.crypto.bls.BLS12_381BasicScheme;
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
}
