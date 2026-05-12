package org.bouncycastle.crypto.hash2curve.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.bls.BLS12_381BasicScheme;
import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.crypto.bls.BLS12_381SubgroupCheck;
import org.bouncycastle.crypto.generators.BLSKeyPairGenerator;
import org.bouncycastle.crypto.params.BLSKeyGenerationParameters;
import org.bouncycastle.crypto.params.BLSParameters;
import org.bouncycastle.crypto.params.BLSPrivateKeyParameters;
import org.bouncycastle.crypto.params.BLSPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;

public class BLSKeyPairGeneratorTest
    extends TestCase
{
    public void testGeneratesValidKeyPair()
    {
        BLSKeyPairGenerator gen = new BLSKeyPairGenerator();
        gen.init(new BLSKeyGenerationParameters(
            new SecureRandom(new byte[]{1}), BLSParameters.bls12_381));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        BLSPublicKeyParameters pk = (BLSPublicKeyParameters)kp.getPublic();
        BLSPrivateKeyParameters sk = (BLSPrivateKeyParameters)kp.getPrivate();

        assertSame(BLSParameters.bls12_381, pk.getParameters());
        assertSame(BLSParameters.bls12_381, sk.getParameters());

        // sk must be in [1, r-1] — enforced by the ctor; just sanity-check signum.
        assertTrue("sk must be positive", sk.getSecret().signum() > 0);

        // pk must be on the curve and in G1.
        assertTrue("pk must be a valid G1 point",
            BLS12_381BasicScheme.keyValidate(pk.getPublicPoint()));

        // sk and pk must agree: sk * G1_gen == pk.
        assertEquals("skToPk(sk) must equal pk",
            BLS12_381BasicScheme.skToPk(sk.getSecret()), pk.getPublicPoint());
    }

    public void testSignVerifyWithGeneratedKey()
    {
        BLSKeyPairGenerator gen = new BLSKeyPairGenerator();
        gen.init(new BLSKeyGenerationParameters(
            new SecureRandom(new byte[]{2}), BLSParameters.bls12_381));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        BLSPublicKeyParameters pk = (BLSPublicKeyParameters)kp.getPublic();
        BLSPrivateKeyParameters sk = (BLSPrivateKeyParameters)kp.getPrivate();

        byte[] msg = Strings.toUTF8ByteArray("BLSKeyPairGenerator sanity check");
        BLS12_381G2Point sig = BLS12_381BasicScheme.sign(sk.getSecret(), msg);
        assertTrue(BLS12_381BasicScheme.verify(pk.getPublicPoint(), msg, sig));
    }

    public void testDeterministicForFixedIkm()
    {
        // Use BC's FixedSecureRandom to make the IKM-byte sequence
        // explicitly identical across two runs. The KeyGen procedure is
        // deterministic given the same IKM, so the secret keys must match.
        byte[] ikm = new byte[32];
        for (int i = 0; i < ikm.length; ++i) ikm[i] = (byte)(i + 1);

        AsymmetricCipherKeyPair a = generateFromIkm(ikm);
        AsymmetricCipherKeyPair b = generateFromIkm(ikm);
        assertEquals(
            ((BLSPrivateKeyParameters)a.getPrivate()).getSecret(),
            ((BLSPrivateKeyParameters)b.getPrivate()).getSecret());
    }

    public void testDifferentIkmGiveDifferentKeys()
    {
        byte[] ikm1 = new byte[32];
        byte[] ikm2 = new byte[32];
        for (int i = 0; i < 32; ++i)
        {
            ikm1[i] = (byte)(i + 1);
            ikm2[i] = (byte)(i + 2);
        }
        AsymmetricCipherKeyPair a = generateFromIkm(ikm1);
        AsymmetricCipherKeyPair b = generateFromIkm(ikm2);
        assertFalse(((BLSPrivateKeyParameters)a.getPrivate()).getSecret()
            .equals(((BLSPrivateKeyParameters)b.getPrivate()).getSecret()));
    }

    private static AsymmetricCipherKeyPair generateFromIkm(byte[] ikm)
    {
        BLSKeyPairGenerator gen = new BLSKeyPairGenerator();
        gen.init(new BLSKeyGenerationParameters(
            new org.bouncycastle.crypto.prng.FixedSecureRandom(ikm),
            BLSParameters.bls12_381));
        return gen.generateKeyPair();
    }

    public void testGeneratedPubkeyPassesG1SubgroupCheck()
    {
        BLSKeyPairGenerator gen = new BLSKeyPairGenerator();
        gen.init(new BLSKeyGenerationParameters(
            new SecureRandom(new byte[]{3}), BLSParameters.bls12_381));
        BLSPublicKeyParameters pk = (BLSPublicKeyParameters)gen.generateKeyPair().getPublic();
        assertTrue("generator output must be in G1 prime-order subgroup",
            BLS12_381SubgroupCheck.isInG1Subgroup(pk.getPublicPoint()));
    }

    public void testEncodedPubkeyIs48Bytes()
    {
        BLSKeyPairGenerator gen = new BLSKeyPairGenerator();
        gen.init(new BLSKeyGenerationParameters(
            new SecureRandom(new byte[]{4}), BLSParameters.bls12_381));
        BLSPublicKeyParameters pk = (BLSPublicKeyParameters)gen.generateKeyPair().getPublic();
        assertEquals("Zcash compressed G1 encoding is 48 bytes", 48, pk.getEncoded().length);
    }

    private static AsymmetricCipherKeyPair generate(int seed)
    {
        BLSKeyPairGenerator gen = new BLSKeyPairGenerator();
        gen.init(new BLSKeyGenerationParameters(
            new SecureRandom(new byte[]{(byte)seed}), BLSParameters.bls12_381));
        return gen.generateKeyPair();
    }

    // ---------------------------------------------------------------------
    // BLSPublicKeyParameters constructor invariant tests (W2 in the review).
    //
    // Before the fix the constructor was a thin wrapper that just normalised
    // the point — meaning callers could construct a "BLS public key" type
    // wrapping any ECPoint (null, identity, off-curve, off-subgroup). The
    // fix runs draft-irtf-cfrg-bls-signature sec. 2.5 KeyValidate at
    // construction so the type now actually guarantees what its name
    // claims. These tests pin the invariant.
    // ---------------------------------------------------------------------

    public void testPublicKeyParametersRejectsNull()
    {
        try
        {
            new BLSPublicKeyParameters(BLSParameters.bls12_381, null);
            fail("null public point should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testPublicKeyParametersRejectsIdentity()
    {
        // The point at infinity passes curve-equation / subgroup checks
        // (identity is in every subgroup) but is explicitly rejected by
        // KeyValidate step 3.
        ECCurve curve = BLS12_381G1.createCurve();
        try
        {
            new BLSPublicKeyParameters(BLSParameters.bls12_381, curve.getInfinity());
            fail("identity / infinity public point should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testPublicKeyParametersRejectsOffSubgroup()
    {
        // Construct a point on E(Fp) that is NOT in the prime-order G1
        // subgroup. Strategy: pick a random x in [0, p), solve for y from
        // y^2 = x^3 + 4 mod p (p ≡ 3 mod 4 so sqrt is x^((p+1)/4)). With
        // probability ≈ 1/cofactor (cofactor for BLS12-381 G1 is ~2^126)
        // the recovered point is in G1, so a few attempts almost always
        // yields an off-subgroup curve point.
        SecureRandom rng = new SecureRandom();
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
                // rhs is not a quadratic residue; pick a different x.
                continue;
            }
            ECPoint candidate = curve.createPoint(x, y);
            if (BLS12_381SubgroupCheck.isInG1Subgroup(candidate))
            {
                // Astronomically improbable; just try another.
                continue;
            }
            try
            {
                new BLSPublicKeyParameters(BLSParameters.bls12_381, candidate);
                fail("off-subgroup G1 point should be rejected by the BLSPublicKeyParameters constructor");
            }
            catch (IllegalArgumentException expected)
            {
            }
            return;
        }
        fail("could not construct an off-subgroup G1 point in 16 attempts (statistically unreachable)");
    }

    public void testPublicKeyParametersAcceptsValidPoint()
    {
        // Sanity: a freshly-generated keypair's pk passes the constructor.
        // (The generator constructs BLSPublicKeyParameters internally, so
        // if W2 broke skToPk output the generator would throw at line 54
        // of BLSKeyPairGenerator. Repeat the check explicitly here so a
        // diff to BLSPublicKeyParameters surfaces against this test.)
        ECPoint validPk = BLS12_381BasicScheme.skToPk(
            BLS12_381BasicScheme.keyGen(new byte[32], new byte[0]));
        BLSPublicKeyParameters pk = new BLSPublicKeyParameters(
            BLSParameters.bls12_381, validPk);
        assertEquals(validPk.normalize(), pk.getPublicPoint());
    }

    // ---------------------------------------------------------------------
    // BLSPrivateKeyParameters constructor invariant tests (review gap G4).
    //
    // Symmetric coverage to the BLSPublicKeyParameters tests above. The
    // constructor enforces 0 < sk < r (BLS12_381G1.ORDER); each
    // out-of-range value should throw IllegalArgumentException.
    // ---------------------------------------------------------------------

    public void testPrivateKeyParametersRejectsNull()
    {
        try
        {
            new BLSPrivateKeyParameters(BLSParameters.bls12_381, null);
            fail("null secret should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testPrivateKeyParametersRejectsZero()
    {
        try
        {
            new BLSPrivateKeyParameters(BLSParameters.bls12_381, java.math.BigInteger.ZERO);
            fail("sk = 0 should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testPrivateKeyParametersRejectsNegative()
    {
        try
        {
            new BLSPrivateKeyParameters(BLSParameters.bls12_381,
                java.math.BigInteger.valueOf(-1));
            fail("sk = -1 should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testPrivateKeyParametersRejectsAtOrder()
    {
        try
        {
            new BLSPrivateKeyParameters(BLSParameters.bls12_381, BLS12_381G1.ORDER);
            fail("sk = r should be rejected (must be in [1, r-1])");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testPrivateKeyParametersRejectsAboveOrder()
    {
        try
        {
            new BLSPrivateKeyParameters(BLSParameters.bls12_381,
                BLS12_381G1.ORDER.add(java.math.BigInteger.ONE));
            fail("sk = r + 1 should be rejected");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }

    public void testPrivateKeyParametersAcceptsBoundaryValues()
    {
        // sk = 1 and sk = r - 1 are the inclusive boundaries.
        new BLSPrivateKeyParameters(BLSParameters.bls12_381, java.math.BigInteger.ONE);
        new BLSPrivateKeyParameters(BLSParameters.bls12_381,
            BLS12_381G1.ORDER.subtract(java.math.BigInteger.ONE));
    }

    // ---------------------------------------------------------------------
    // BLSKeyPairGenerator init / generate guard rails (review gaps G15, G16).
    // ---------------------------------------------------------------------

    public void testGenerateBeforeInitThrows()
    {
        BLSKeyPairGenerator gen = new BLSKeyPairGenerator();
        try
        {
            gen.generateKeyPair();
            fail("generateKeyPair before init must throw");
        }
        catch (IllegalStateException expected)
        {
        }
    }

    public void testInitRejectsWrongParamType()
    {
        BLSKeyPairGenerator gen = new BLSKeyPairGenerator();
        try
        {
            // ECKeyGenerationParameters is the conventional "wrong but
            // structurally similar" sibling — pass anything that isn't
            // BLSKeyGenerationParameters and confirm rejection.
            gen.init(new org.bouncycastle.crypto.params.ECKeyGenerationParameters(
                new org.bouncycastle.crypto.params.ECDomainParameters(
                    BLS12_381G1.createCurve(),
                    BLS12_381G1.getGenerator(BLS12_381G1.createCurve()),
                    BLS12_381G1.ORDER, BLS12_381G1.COFACTOR),
                new SecureRandom()));
            fail("init with non-BLSKeyGenerationParameters must throw");
        }
        catch (IllegalArgumentException expected)
        {
        }
    }
}
