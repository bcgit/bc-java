package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKEMExtractor;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKEMGenerator;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTKeyPairGenerator;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTParameters;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTPublicKeyParameters;

public class SmaugTTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        SmaugTTest test = new SmaugTTest();
        test.testTestVectors();
    }

    private static final SmaugTParameters[] PARAMETER_SETS = new SmaugTParameters[]
        {
            SmaugTParameters.smaugt_mode1,
            SmaugTParameters.smaugt_mode3,
            SmaugTParameters.smaugt_mode5,
            SmaugTParameters.smaugt_modet
        };

    private static final String[] files = new String[]{
        "PQCkemKAT_smaugt_mode1.rsp",
        "PQCkemKAT_smaugt_mode3.rsp",
        "PQCkemKAT_smaugt_mode5.rsp",
        "PQCkemKAT_smaugt_modet.rsp"
    };

    public void testTestVectors()
        throws Exception
    {
        long start = System.currentTimeMillis();
        TestUtils.testTestVector(true, false, "pqc/crypto/smaug_t", files, new TestUtils.KeyEncapsulationOperation()
        {
            int sessionKeySize = 0;

            @Override
            public SecureRandom getSecureRandom(byte[] seed)
            {
                return new NISTSecureRandom(seed, null);
            }

            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
                SmaugTParameters parameters = PARAMETER_SETS[fileIndex];
                sessionKeySize = parameters.getSessionKeySize();
                SmaugTKeyPairGenerator kpGen = new SmaugTKeyPairGenerator();
                kpGen.init(new SmaugTKeyGenerationParameters(random, parameters));
                return kpGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams)
            {
                return ((SmaugTPublicKeyParameters)pubParams).getPublicKey();
            }

            @Override
            public byte[] getPrivateKeyEncoded(AsymmetricKeyParameter privParams)
            {
                return ((SmaugTPrivateKeyParameters)privParams).getPrivateKey();
            }

            @Override
            public EncapsulatedSecretGenerator getKEMGenerator(SecureRandom random)
            {
                return new SmaugTKEMGenerator(random);
            }

            @Override
            public EncapsulatedSecretExtractor getKEMExtractor(AsymmetricKeyParameter privParams)
            {
                return new SmaugTKEMExtractor((SmaugTPrivateKeyParameters)privParams);
            }

            @Override
            public int getSessionKeySize()
            {
                return sessionKeySize;
            }
        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }
}
