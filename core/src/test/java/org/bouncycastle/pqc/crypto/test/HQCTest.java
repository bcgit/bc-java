package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHAKEDigest;
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

    public void testVectors()
        throws Exception
    {
        String[] files;
        // test cases
        files = new String[]{
            "PQCkemKAT_2321.rsp",
            "PQCkemKAT_4602.rsp",
            "PQCkemKAT_7333.rsp",
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
                return new Shake256SecureRandom(seed);
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
                assertEquals(parameters.getSessionKeySize() / 8, encapSecret.length);
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
    
    private static class Shake256SecureRandom
        extends SecureRandom
    {
        private final SHAKEDigest xof = new SHAKEDigest(256);

        Shake256SecureRandom(byte[] seed)
        {
            xof.update(seed, 0, seed.length);
            xof.update((byte) 0);
        }

        public void nextBytes(byte[] bytes)
        {
            xof.doOutput(bytes, 0, bytes.length);
        }
    }
}
