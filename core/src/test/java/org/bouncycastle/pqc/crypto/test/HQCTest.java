package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMExtractor;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPublicKeyParameters;
import org.bouncycastle.util.Arrays;

public class HQCTest
    extends TestCase
{
    private final SecureRandom RANDOM = new SecureRandom();

    public void testConsistencyHQC128()
    {
        implTestConsistency(HQCParameters.hqc128);
    }

    public void testConsistencyHQC192()
    {
        implTestConsistency(HQCParameters.hqc192);
    }

    public void testConsistencyHQC256()
    {
        implTestConsistency(HQCParameters.hqc256);
    }

    public void testImplicitRejectionCoverageHQC128()
    {
        implTestImplicitRejectionCoverage(HQCParameters.hqc128);
    }

    public void testImplicitRejectionCoverageHQC192()
    {
        implTestImplicitRejectionCoverage(HQCParameters.hqc192);
    }

    public void testImplicitRejectionCoverageHQC256()
    {
        implTestImplicitRejectionCoverage(HQCParameters.hqc256);
    }

    public void testSeedOnlyPrivateKeyHQC128()
    {
        implTestSeedOnlyPrivateKey(HQCParameters.hqc128);
    }

    public void testSeedOnlyPrivateKeyHQC192()
    {
        implTestSeedOnlyPrivateKey(HQCParameters.hqc192);
    }

    public void testSeedOnlyPrivateKeyHQC256()
    {
        implTestSeedOnlyPrivateKey(HQCParameters.hqc256);
    }

    public void testVectors()
        throws Exception
    {
        String[] files;
        // test cases
        // the reference implementation's kats/ref/hqc-{1,3,5}/PQCkemKAT_32.rsp for the HQC
        // specification of 2026-10-12 (32 is the size of the seed-only decapsulation key)
        files = new String[]{
            "hqc-1/PQCkemKAT_32.rsp",
            "hqc-3/PQCkemKAT_32.rsp",
            "hqc-5/PQCkemKAT_32.rsp",
        };

        final HQCParameters[] listParams = new HQCParameters[]{
            HQCParameters.hqc128,
            HQCParameters.hqc192,
            HQCParameters.hqc256
        };

        TestUtils.testTestVector(true, true, "pqc/crypto/hqc", files, new TestUtils.KeyEncapsulationOperation()
        {
            int sessionKeySize = 0;

            @Override
            public SecureRandom getSecureRandom(byte[] seed)
            {
                // the 2026-10-12 reference KAT harness went back to the NIST AES-256 CTR-DRBG
                // (lib/nist-rng/rng.c, randombytes_init(seed, NULL, 256)); the 2025-08-22 one drew from
                // SHAKE256(seed || 0x00)
                return new NISTSecureRandom(seed, null);
            }

            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
                HQCParameters parameters = listParams[fileIndex];
                sessionKeySize = parameters.getSessionKeySize();
                HQCKeyPairGenerator hqcKeyGen = new HQCKeyPairGenerator();
                HQCKeyGenerationParameters genParam = new HQCKeyGenerationParameters(random, parameters);
                hqcKeyGen.init(genParam);
                return hqcKeyGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams)
            {
                return ((HQCPublicKeyParameters)pubParams).getPublicKey();
            }

            @Override
            public byte[] getPrivateKeyEncoded(AsymmetricKeyParameter privParams)
            {
                return ((HQCPrivateKeyParameters)privParams).getPrivateKey();
            }

            @Override
            public EncapsulatedSecretGenerator getKEMGenerator(SecureRandom random)
            {
                return new HQCKEMGenerator(random);
            }

            @Override
            public EncapsulatedSecretExtractor getKEMExtractor(AsymmetricKeyParameter privParams)
            {
                return new HQCKEMExtractor((HQCPrivateKeyParameters)privParams);
            }

            @Override
            public int getSessionKeySize()
            {
                return sessionKeySize;
            }
        });
    }

    /**
     * The decapsulation key encoding is the 32-byte seedKEM (HQC specification 2026-10-12, Table 9):
     * a key rebuilt from nothing but that encoding must derive the same public key and decapsulate,
     * and the superseded expanded encoding must be refused.
     */
    private void implTestSeedOnlyPrivateKey(HQCParameters parameters)
    {
        HQCKeyPairGenerator kpg = new HQCKeyPairGenerator();
        kpg.init(new HQCKeyGenerationParameters(RANDOM, parameters));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        HQCPublicKeyParameters pub = (HQCPublicKeyParameters)kp.getPublic();
        HQCPrivateKeyParameters priv = (HQCPrivateKeyParameters)kp.getPrivate();

        byte[] enc = priv.getEncoded();
        assertEquals(parameters.getName() + ": secret key size", 32, parameters.getSecretKeyBytes());
        assertEquals(parameters.getName() + ": encoding size", 32, enc.length);
        assertTrue(parameters.getName() + ": getPrivateKey", Arrays.areEqual(enc, priv.getPrivateKey()));

        // the generator's own copy and a key re-derived from the seed agree on the public key
        assertTrue(parameters.getName() + ": public key from seed",
            Arrays.areEqual(pub.getEncoded(), priv.getPublicKeyParameters().getEncoded()));

        HQCPrivateKeyParameters rebuilt = new HQCPrivateKeyParameters(parameters, enc);
        assertTrue(parameters.getName() + ": public key from rebuilt seed",
            Arrays.areEqual(pub.getEncoded(), rebuilt.getPublicKeyParameters().getEncoded()));

        SecretWithEncapsulation encapsulated = new HQCKEMGenerator(RANDOM).generateEncapsulated(pub);
        byte[] fromRebuilt = new HQCKEMExtractor(rebuilt).extractSecret(encapsulated.getEncapsulation());
        assertTrue(parameters.getName() + ": decaps with rebuilt key", Arrays.areEqual(encapsulated.getSecret(), fromRebuilt));

        // the expanded layout of the 2025-08-22 specification is no longer an encoding
        int[] oldSizes = new int[]{2321, 4602, 7333};
        for (int i = 0; i != oldSizes.length; i++)
        {
            try
            {
                new HQCPrivateKeyParameters(parameters, new byte[oldSizes[i]]);
                fail(parameters.getName() + ": accepted a " + oldSizes[i] + " byte private key");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("'sk' has invalid length", e.getMessage());
            }
        }
    }

    private void implTestConsistency(HQCParameters parameters)
    {
        HQCKeyPairGenerator kpg = new HQCKeyPairGenerator();
        kpg.init(new HQCKeyGenerationParameters(RANDOM, parameters));

        for (int i = 0; i < 10; ++i)
        {
            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

            for (int j = 0; j < 10; ++j)
            {
                HQCKEMGenerator generator = new HQCKEMGenerator(RANDOM);
                SecretWithEncapsulation encapsulated = generator.generateEncapsulated(kp.getPublic());
                byte[] encapSecret = encapsulated.getSecret();
                byte[] encapsulation = encapsulated.getEncapsulation();
                assertEquals(parameters.getSessionKeySize(), encapSecret.length * 8);
                assertEquals(parameters.getSecretLength(), encapSecret.length);
                assertEquals(parameters.getEncapsulationLength(), encapsulation.length);

                HQCKEMExtractor extractor = new HQCKEMExtractor((HQCPrivateKeyParameters)kp.getPrivate());
                byte[] decapSecret = extractor.extractSecret(encapsulation);
                if (!Arrays.areEqual(encapSecret, decapSecret))
                {
                    fail("Consistency " + parameters.getName() + " #" + i + "[" + j + "]");
                }
            }
        }
    }

    private void implTestImplicitRejectionCoverage(HQCParameters parameters)
    {
        // Regression test for the FO implicit-rejection / IND-CCA property: on re-encryption
        // failure the returned secret must be derived solely from (sigma, ciphertext) and must
        // NOT leak the decrypted message m'. Previously the conditional-move was bounded by the
        // message length k (16 for HQC-128, 24 for HQC-192) rather than the 32-byte secret, so
        // the trailing bytes kept K' = G(H(pk) || m' || salt) and gave a plaintext-checking oracle.
        HQCKeyPairGenerator kpg = new HQCKeyPairGenerator();
        kpg.init(new HQCKeyGenerationParameters(RANDOM, parameters));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        HQCKEMGenerator generator = new HQCKEMGenerator(RANDOM);
        SecretWithEncapsulation encapsulated = generator.generateEncapsulated(kp.getPublic());
        byte[] validSecret = encapsulated.getSecret();
        byte[] ct = encapsulated.getEncapsulation();

        HQCKEMExtractor extractor = new HQCKEMExtractor((HQCPrivateKeyParameters)kp.getPrivate());

        // Sanity: an untampered ciphertext decapsulates to the encapsulated secret.
        assertTrue(parameters + ": valid decaps", Arrays.areEqual(validSecret, extractor.extractSecret(ct)));

        // The 'v' part of the ciphertext follows 'u', which is N_BYTE = PublicKeyBytes - 32 bytes
        // long (the public key is a 32-byte seed plus the N_BYTE syndrome). A single-bit flip in v
        // stays within the Reed-Muller/Reed-Solomon correction capacity, so the decoded m' (and
        // hence the salt) is unchanged while the re-encryption check fails. Two such ciphertexts
        // therefore share the same (m', salt) but differ as byte strings.
        int vOffset = parameters.getPublicKeyBytes() - 32;

        byte[] ct1 = Arrays.clone(ct);
        byte[] ct2 = Arrays.clone(ct);
        ct1[vOffset] ^= 0x01;
        ct2[vOffset] ^= 0x02;

        byte[] rej1 = extractor.extractSecret(ct1);
        byte[] rej2 = extractor.extractSecret(ct2);

        // Both must be genuine rejections, not the valid secret.
        assertFalse(parameters + ": ct1 not rejected", Arrays.areEqual(validSecret, rej1));
        assertFalse(parameters + ": ct2 not rejected", Arrays.areEqual(validSecret, rej2));

        // Rejection must be deterministic in (sk, ct).
        assertTrue(parameters + ": rejection not deterministic", Arrays.areEqual(rej1, extractor.extractSecret(ct1)));

        // The trailing 8 bytes lie in the vulnerable region for every parameter set (k <= 32),
        // and must depend on the differing ciphertext. With the bug they were a copy of K',
        // identical for ct1 and ct2.
        byte[] tail1 = Arrays.copyOfRange(rej1, 24, 32);
        byte[] tail2 = Arrays.copyOfRange(rej2, 24, 32);
        assertFalse(parameters + ": rejection secret tail must depend on the ciphertext (FO implicit rejection)",
            Arrays.areEqual(tail1, tail2));
    }
}
