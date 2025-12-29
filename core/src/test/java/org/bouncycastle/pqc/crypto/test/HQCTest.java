package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMExtractor;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPublicKeyParameters;

public class HQCTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        HQCTest test = new HQCTest();
        test.testVectors();
    }

    @Override
    public String getName()
    {
        return "HQC Test";
    }

    public void testVectors()
        throws Exception
    {
        boolean full = System.getProperty("test.full", "false").equals("true");

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

    private static class Shake256SecureRandom
        extends SecureRandom
    {
        private final SHAKEDigest digest = new SHAKEDigest(256);

        Shake256SecureRandom(byte[] seed)
        {
            digest.update(seed, 0, seed.length);
            digest.update((byte) 0);
        }

        public void nextBytes(byte[] bytes)
        {
            digest.doOutput(bytes, 0, bytes.length);
        }
    }
}
