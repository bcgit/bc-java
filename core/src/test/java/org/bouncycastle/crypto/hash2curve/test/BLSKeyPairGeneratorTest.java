package org.bouncycastle.crypto.hash2curve.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.bls.BLS12_381BasicScheme;
import org.bouncycastle.crypto.bls.BLS12_381G2Point;
import org.bouncycastle.crypto.bls.BLS12_381SubgroupCheck;
import org.bouncycastle.crypto.generators.BLSKeyPairGenerator;
import org.bouncycastle.crypto.params.BLSKeyGenerationParameters;
import org.bouncycastle.crypto.params.BLSParameters;
import org.bouncycastle.crypto.params.BLSPrivateKeyParameters;
import org.bouncycastle.crypto.params.BLSPublicKeyParameters;
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
}
