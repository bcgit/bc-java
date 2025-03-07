package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.snova.SnovaKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaKeyPairGenerator;
import org.bouncycastle.pqc.crypto.snova.SnovaParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaPublicKeyParameters;


public class SnovaTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        SnovaTest test = new SnovaTest();
        test.testTestVectors();
    }

    private static final SnovaParameters[] PARAMETER_SETS = new SnovaParameters[]
        {
            SnovaParameters.SNOVA_24_5_16_4_ESK,
        };

    private static final String[] files = new String[]{
        "PQCsignKAT_SNOVA_24_5_4_ESK.rsp",
    };


    public void testTestVectors()
        throws Exception
    {
        long start = System.currentTimeMillis();
        TestUtils.testTestVector(false, false, "pqc/crypto/snova", files, new TestUtils.KeyGenerationOperation()
        {
            @Override
            public SecureRandom getSecureRanom(byte[] seed)
            {
                return new NISTSecureRandom(seed, null);
            }

            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
                SnovaParameters parameters = PARAMETER_SETS[fileIndex];

                SnovaKeyPairGenerator kpGen = new SnovaKeyPairGenerator();
                kpGen.init(new SnovaKeyGenerationParameters(random, parameters));
                return kpGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams)
            {
                return ((SnovaPublicKeyParameters)pubParams).getEncoded();
            }

            @Override
            public byte[] getPrivateKeyEncoded(CipherParameters privParams)
            {
                return ((SnovaPrivateKeyParameters)privParams).getEncoded();
            }

            @Override
            public Signer getSigner()
            {
                return null;
            }

            @Override
            public MessageSigner getMessageSigner()
            {
                return null;//new SnovaSigner();
            }
        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }
}

