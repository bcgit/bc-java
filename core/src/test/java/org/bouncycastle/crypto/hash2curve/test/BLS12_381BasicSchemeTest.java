package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.bls.BLS12_381BasicScheme;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.crypto.bls.BLS12_381SubgroupCheck;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;

/**
 * Functional tests for the BLS12-381 BasicScheme signer/verifier
 * (draft-irtf-cfrg-bls-signature, suite
 * {@code BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_}).
 */
public class BLS12_381BasicSchemeTest
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

    public void testKeyGenIsDeterministic()
    {
        byte[] ikm = ikm32(0);
        BigInteger sk1 = BLS12_381BasicScheme.keyGen(ikm, new byte[0]);
        BigInteger sk2 = BLS12_381BasicScheme.keyGen(ikm, new byte[0]);
        assertEquals(sk1, sk2);
        assertTrue("sk must be in [1, r-1]", sk1.signum() > 0);
        assertTrue("sk must be in [1, r-1]", sk1.compareTo(BLS12_381G1.ORDER) < 0);
    }

    public void testKeyGenSeparation()
    {
        byte[] ikm = ikm32(0);
        BigInteger sk1 = BLS12_381BasicScheme.keyGen(ikm, Strings.toUTF8ByteArray("ctx-A"));
        BigInteger sk2 = BLS12_381BasicScheme.keyGen(ikm, Strings.toUTF8ByteArray("ctx-B"));
        assertFalse("different keyInfo must yield different sk", sk1.equals(sk2));
    }

    public void testKeyGenRequiresMin32ByteIkm()
    {
        try
        {
            BLS12_381BasicScheme.keyGen(new byte[31], new byte[0]);
            fail("31-byte IKM should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testSkToPkValidPoint()
    {
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(1), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        assertTrue("skToPk must produce a valid G1 point", BLS12_381BasicScheme.keyValidate(pk));
    }

    public void testKeyValidateRejectsIdentity()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        assertFalse(BLS12_381BasicScheme.keyValidate(curve.getInfinity()));
    }

    public void testSignVerifyRoundTrip()
    {
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(2), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        byte[] msg = Strings.toUTF8ByteArray("hello, BLS");

        BLS12_381G2Point sig = BLS12_381BasicScheme.sign(sk, msg);
        assertTrue("valid signature must verify", BLS12_381BasicScheme.verify(pk, msg, sig));
    }

    public void testSignIsDeterministic()
    {
        // BLS signatures are deterministic: sig = sk * H(msg) and the
        // hash-to-curve is deterministic.
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(3), new byte[0]);
        byte[] msg = Strings.toUTF8ByteArray("deterministic check");
        BLS12_381G2Point sig1 = BLS12_381BasicScheme.sign(sk, msg);
        BLS12_381G2Point sig2 = BLS12_381BasicScheme.sign(sk, msg);
        assertEquals(sig1, sig2);
    }

    public void testVerifyRejectsWrongMessage()
    {
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(4), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        BLS12_381G2Point sig = BLS12_381BasicScheme.sign(sk, Strings.toUTF8ByteArray("original"));
        assertFalse("signature for one message must not verify under another",
            BLS12_381BasicScheme.verify(pk, Strings.toUTF8ByteArray("tampered"), sig));
    }

    public void testVerifyRejectsWrongPublicKey()
    {
        BigInteger sk1 = BLS12_381BasicScheme.keyGen(ikm32(5), new byte[0]);
        BigInteger sk2 = BLS12_381BasicScheme.keyGen(ikm32(6), new byte[0]);
        ECPoint pk2 = BLS12_381BasicScheme.skToPk(sk2);

        byte[] msg = Strings.toUTF8ByteArray("wrong-pk test");
        BLS12_381G2Point sig = BLS12_381BasicScheme.sign(sk1, msg);
        assertFalse("signature must not verify under a different public key",
            BLS12_381BasicScheme.verify(pk2, msg, sig));
    }

    public void testVerifyRejectsTamperedSignature()
    {
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(7), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        byte[] msg = Strings.toUTF8ByteArray("tamper test");
        BLS12_381G2Point sig = BLS12_381BasicScheme.sign(sk, msg);
        // Add G2 generator to the signature: still on the curve, but no
        // longer the correct sk * H(msg).
        BLS12_381G2Point bad = sig.add(org.bouncycastle.crypto.bls.BLS12_381G2.getGenerator());
        assertFalse("tampered signature must not verify",
            BLS12_381BasicScheme.verify(pk, msg, bad));
    }

    public void testVerifyRejectsInfinitySignature()
    {
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(8), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        assertFalse("infinity signature must not verify",
            BLS12_381BasicScheme.verify(pk, Strings.toUTF8ByteArray("any"), BLS12_381G2Point.INFINITY));
    }

    // ---------------------------------------------------------------------
    // keyValidate negative-branch coverage (review gap G3).
    //
    // The existing testKeyValidateRejectsIdentity exercises the
    // non-identity guard. keyValidate also rejects null, off-curve and
    // off-subgroup points; all three are pinned below.
    // ---------------------------------------------------------------------

    public void testKeyValidateRejectsNull()
    {
        assertFalse("null public key must be rejected",
            BLS12_381BasicScheme.keyValidate(null));
    }

    public void testKeyValidateRejectsOffSubgroup()
    {
        // Construct a point on E(Fp) that is NOT in the prime-order G1
        // subgroup (same approach as
        // BLSKeyPairGeneratorTest.testPublicKeyParametersRejectsOffSubgroup).
        // A random curve point lands in G1 with probability ~1/cofactor
        // (cofactor ~2^126), so a handful of attempts is plenty.
        SecureRandom rng = new SecureRandom(new byte[]{91});
        BigInteger p = BLS12_381G1.Q;
        ECCurve curve = BLS12_381G1.createCurve();
        for (int attempt = 0; attempt < 16; ++attempt)
        {
            BigInteger x = new BigInteger(p.bitLength(), rng).mod(p);
            BigInteger rhs = x.modPow(BigInteger.valueOf(3), p)
                .add(BigInteger.valueOf(4)).mod(p);
            BigInteger y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
            if (!y.multiply(y).mod(p).equals(rhs))
            {
                continue;
            }
            ECPoint candidate = curve.createPoint(x, y);
            if (BLS12_381SubgroupCheck.isInG1Subgroup(candidate))
            {
                continue;
            }
            assertFalse("off-subgroup G1 point must fail keyValidate",
                BLS12_381BasicScheme.keyValidate(candidate));
            return;
        }
        fail("could not construct an off-subgroup G1 point in 16 attempts");
    }

    /** (0, 2) is on the curve and has order 3, so it is outside G1. */
    public void testKeyValidateRejectsSmallOrder()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint order3 = curve.createPoint(BigInteger.ZERO, BigInteger.valueOf(2));
        assertTrue(order3.twice().equals(order3.negate()));
        assertFalse("order-3 point must fail keyValidate", BLS12_381BasicScheme.keyValidate(order3));
        assertFalse(BLS12_381SubgroupCheck.isInG1Subgroup(order3));
    }

    /**
     * ECCurve.createPoint does not check the curve equation, and the G1 subgroup
     * check never uses b, so it accepts the image (u^2 x, u^3 y) of a G1 point
     * on the isomorphic curve y^2 = x^3 + 4u^6. keyValidate must reject it by
     * the curve equation.
     */
    public void testKeyValidateRejectsOffCurve()
    {
        ECCurve curve = BLS12_381G1.createCurve();
        ECPoint g = BLS12_381G1.getGenerator(curve);
        BigInteger p = BLS12_381G1.Q;
        BigInteger u = BigInteger.valueOf(2);
        ECPoint image = curve.createPoint(g.getAffineXCoord().toBigInteger().multiply(u.pow(2)).mod(p),
            g.getAffineYCoord().toBigInteger().multiply(u.pow(3)).mod(p));
        assertFalse("image must be off the curve", image.isValid());
        assertTrue("the subgroup check alone accepts the image",
            BLS12_381SubgroupCheck.isInG1Subgroup(image));
        assertFalse("off-curve point must fail keyValidate", BLS12_381BasicScheme.keyValidate(image));

        ECPoint tampered = curve.createPoint(g.getAffineXCoord().toBigInteger(),
            g.getAffineYCoord().toBigInteger().add(BigInteger.ONE));
        assertFalse("off-curve point must fail keyValidate", BLS12_381BasicScheme.keyValidate(tampered));
    }

    // A point names its own ECCurve, and ECPoint.satisfiesOrder() trusts that curve's own
    // cofactor - so a point on a foreign curve that merely shares BLS12-381's field, with
    // its cofactor forged to 1, would trivially pass the subgroup check unless keyValidate
    // first confirms the curve itself is canonical BLS12-381 G1 (phantom aggregate signer,
    // feedback-crypto report from bshastry@posteo.de).
    public void testKeyValidateRejectsForeignCurveSharingField()
    {
        // y^2 = x^3 + x over the real field Q, with order/cofactor forged to 1: (0,0)
        // satisfies this equation and trivially "satisfies" a cofactor-1 subgroup check.
        ECCurve foreign = new ECCurve.Fp(BLS12_381G1.Q, BigInteger.ONE, BigInteger.ZERO,
            BigInteger.ONE, BigInteger.ONE);
        ECPoint phantom = foreign.createPoint(BigInteger.ZERO, BigInteger.ZERO);

        assertFalse("point on a foreign curve sharing BLS12-381's field must be rejected",
            BLS12_381BasicScheme.keyValidate(phantom));
    }

    // ---------------------------------------------------------------------
    // Empty-message round-trip (review gap G8).
    // Eth2 KAT vectors don't include a sign-and-verify with msg = [],
    // and the spec-level scheme tests above all use non-empty messages.
    // expand_message_xmd has explicit handling for empty inputs (the
    // length-prefix turns empty msg into a non-empty hash input); this
    // test pins the end-to-end behaviour.
    // ---------------------------------------------------------------------

    public void testSignVerifyEmptyMessageRoundTrip()
    {
        BigInteger sk = BLS12_381BasicScheme.keyGen(ikm32(9), new byte[0]);
        ECPoint pk = BLS12_381BasicScheme.skToPk(sk);
        byte[] msg = new byte[0];
        BLS12_381G2Point sig = BLS12_381BasicScheme.sign(sk, msg);
        assertTrue("signature over empty message must verify",
            BLS12_381BasicScheme.verify(pk, msg, sig));
        // And must NOT verify under a non-empty distinguishing input.
        assertFalse("empty-msg signature must not verify under a different msg",
            BLS12_381BasicScheme.verify(pk, new byte[]{1}, sig));
    }
}
