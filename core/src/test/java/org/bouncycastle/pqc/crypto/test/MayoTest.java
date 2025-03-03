package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.mayo.MayoKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mayo.MayoParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoPrivateKeyParameter;
import org.bouncycastle.pqc.crypto.mayo.MayoPublicKeyParameter;
import org.bouncycastle.pqc.crypto.mayo.MayoSigner;

public class MayoTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        MayoTest test = new MayoTest();
        test.testTestVectors();
        //test.testKeyGen();
    }

    private static final MayoParameters[] PARAMETER_SETS = new MayoParameters[]
        {
            MayoParameters.MAYO1,
            MayoParameters.MAYO2,
            MayoParameters.MAYO3,
            MayoParameters.MAYO5
        };

    private static final String[] files = new String[]{
        "PQCsignKAT_24_MAYO_1.rsp",
        "PQCsignKAT_24_MAYO_2.rsp",
        "PQCsignKAT_32_MAYO_3.rsp",
        "PQCsignKAT_40_MAYO_5.rsp",
    };


    public void testTestVectors()
        throws Exception
    {
        TestUtils.testTestVector(false, false, "pqc/crypto/mayo", files, new TestUtils.KeyGenerationOperation()
        {
            @Override
            public SecureRandom getSecureRanom(byte[] seed)
            {
                return new NISTSecureRandom(seed, null);
            }

            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
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
            public byte[] getPrivateKeyEncoded(CipherParameters privParams)
            {
                return ((MayoPrivateKeyParameter)privParams).getEncoded();
            }

            @Override
            public Signer getSigner()
            {
                return null;
            }

            @Override
            public MessageSigner getMessageSigner()
            {
                return new MayoSigner();
            }
        });
    }
}
