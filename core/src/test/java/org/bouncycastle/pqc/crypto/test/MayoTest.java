package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.mayo.MayoKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mayo.MayoParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoPrivateKeyParameter;
import org.bouncycastle.pqc.crypto.mayo.MayoPublicKeyParameter;

public class MayoTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        MayoTest test = new MayoTest();
        test.testKeyGen();
    }

    private static final MayoParameters[] PARAMETER_SETS = new MayoParameters[]
        {
            MayoParameters.MAYO1,
            MayoParameters.MAYO2,
            MayoParameters.MAYO3,
            MayoParameters.MAYO5
        };

    public void testKeyGen()
        throws IOException
    {
        String[] files = new String[]{
            "PQCsignKAT_24_MAYO_1.rsp",
            "PQCsignKAT_24_MAYO_2.rsp",
            "PQCsignKAT_32_MAYO_3.rsp",
            "PQCsignKAT_40_MAYO_5.rsp",
        };
        TestUtils.testKeyGen(false, "pqc/crypto/mayo", files, new TestUtils.KeyGenerationOperation()
        {
            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, byte[] seed)
            {
                NISTSecureRandom random = new NISTSecureRandom(seed, null);
                MayoParameters parameters = PARAMETER_SETS[fileIndex];

                MayoKeyPairGenerator kpGen = new MayoKeyPairGenerator();
                kpGen.init(new MayoKeyGenerationParameters(random, parameters));
                return kpGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams)
            {
                return ((MayoPublicKeyParameter)pubParams).getEncoded();
            }

            @Override
            public byte[] getPrivateKeyEncoded(AsymmetricKeyParameter privParams)
            {
                return ((MayoPrivateKeyParameter)privParams).getEncoded();
            }
        });
    }
}
