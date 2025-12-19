package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPublicKeyParameters;

public class NTRUPlusTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        NTRUPlusTest test = new NTRUPlusTest();
        test.testTestVectors();
        //test.testKeyGen();
    }

    private static final NTRUPlusParameters[] PARAMETER_SETS = new NTRUPlusParameters[]
        {
            NTRUPlusParameters.ntruplus_kem_768,
            NTRUPlusParameters.ntruplus_kem_864,
            NTRUPlusParameters.ntruplus_kem_1152,
        };

    private static final String[] files = new String[]{
        "PQCkemKAT_2336.rsp",
        "PQCkemKAT_2624.rsp",
        "PQCkemKAT_3488.rsp",
    };


    public void testTestVectors()
        throws Exception
    {
        long start = System.currentTimeMillis();
        TestUtils.testTestVector(false, true, "pqc/crypto/ntruplus", files, new TestUtils.KeyEncapsulationOperation()
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
                NTRUPlusParameters parameters = PARAMETER_SETS[fileIndex];
                sessionKeySize = parameters.getSsBytes() * 8;
                NTRUPlusKeyPairGenerator kpGen = new NTRUPlusKeyPairGenerator();
                kpGen.init(new NTRUPlusKeyGenerationParameters(random, parameters));
                return kpGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams)
            {
                return ((NTRUPlusPublicKeyParameters)pubParams).getEncoded();
            }

            @Override
            public byte[] getPrivateKeyEncoded(AsymmetricKeyParameter privParams)
            {
                return ((NTRUPlusPrivateKeyParameters)privParams).getEncoded();
            }

            @Override
            public EncapsulatedSecretGenerator getKEMGenerator(SecureRandom random)
            {
                return new NTRUPlusKEMGenerator(random);
            }

            @Override
            public EncapsulatedSecretExtractor getKEMExtractor(AsymmetricKeyParameter privParams)
            {
                return new NTRUPlusKEMExtractor((NTRUPlusPrivateKeyParameters)privParams);
            }

            @Override
            public int getSessionKeySize()
            {
                return 0;
            }

        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }
}
