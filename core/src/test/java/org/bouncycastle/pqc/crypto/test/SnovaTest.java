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
import org.bouncycastle.pqc.crypto.snova.SnovaSigner;


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
            SnovaParameters.SNOVA_24_5_4_ESK,
            SnovaParameters.SNOVA_24_5_4_SHAKE_ESK,
            SnovaParameters.SNOVA_24_5_4_SHAKE_SSK,
            SnovaParameters.SNOVA_24_5_4_SSK,
            SnovaParameters.SNOVA_24_5_5_ESK,
            SnovaParameters.SNOVA_24_5_5_SHAKE_ESK,
            SnovaParameters.SNOVA_24_5_5_SHAKE_SSK,
            SnovaParameters.SNOVA_24_5_5_SSK,
            SnovaParameters.SNOVA_25_8_3_ESK,
            SnovaParameters.SNOVA_25_8_3_SHAKE_ESK,
            SnovaParameters.SNOVA_25_8_3_SHAKE_SSK,
            SnovaParameters.SNOVA_25_8_3_SSK,
            SnovaParameters.SNOVA_29_6_5_ESK,
            SnovaParameters.SNOVA_29_6_5_SHAKE_ESK,
            SnovaParameters.SNOVA_29_6_5_SHAKE_SSK,
            SnovaParameters.SNOVA_29_6_5_SSK,
            SnovaParameters.SNOVA_37_8_4_ESK,
            SnovaParameters.SNOVA_37_8_4_SHAKE_ESK,
            SnovaParameters.SNOVA_37_8_4_SHAKE_SSK,
            SnovaParameters.SNOVA_37_8_4_SSK,
            SnovaParameters.SNOVA_37_17_2_ESK,
            SnovaParameters.SNOVA_37_17_2_SHAKE_ESK,
            SnovaParameters.SNOVA_37_17_2_SHAKE_SSK,
            SnovaParameters.SNOVA_37_17_2_SSK,
            SnovaParameters.SNOVA_49_11_3_ESK,
            SnovaParameters.SNOVA_49_11_3_SHAKE_ESK,
            SnovaParameters.SNOVA_49_11_3_SHAKE_SSK,
            SnovaParameters.SNOVA_49_11_3_SSK,
            SnovaParameters.SNOVA_56_25_2_ESK,
            SnovaParameters.SNOVA_56_25_2_SHAKE_ESK,
            SnovaParameters.SNOVA_56_25_2_SHAKE_SSK,
            SnovaParameters.SNOVA_56_25_2_SSK,
            SnovaParameters.SNOVA_60_10_4_ESK,
            SnovaParameters.SNOVA_60_10_4_SHAKE_ESK,
            SnovaParameters.SNOVA_60_10_4_SHAKE_SSK,
            SnovaParameters.SNOVA_60_10_4_SSK,
            SnovaParameters.SNOVA_66_15_3_ESK,
            SnovaParameters.SNOVA_66_15_3_SHAKE_ESK,
            SnovaParameters.SNOVA_66_15_3_SHAKE_SSK,
            SnovaParameters.SNOVA_66_15_3_SSK,
            SnovaParameters.SNOVA_75_33_2_ESK,
            SnovaParameters.SNOVA_75_33_2_SHAKE_ESK,
            SnovaParameters.SNOVA_75_33_2_SHAKE_SSK,
            SnovaParameters.SNOVA_75_33_2_SSK,
        };

    private static final String[] files = new String[]{
        "PQCsignKAT_SNOVA_24_5_4_ESK.rsp",
        "PQCsignKAT_SNOVA_24_5_4_SHAKE_ESK.rsp",
        "PQCsignKAT_SNOVA_24_5_4_SHAKE_SSK.rsp",
        "PQCsignKAT_SNOVA_24_5_4_SSK.rsp",
        "PQCsignKAT_SNOVA_24_5_5_ESK.rsp",
        "PQCsignKAT_SNOVA_24_5_5_SHAKE_ESK.rsp",
        "PQCsignKAT_SNOVA_24_5_5_SHAKE_SSK.rsp",
        "PQCsignKAT_SNOVA_24_5_5_SSK.rsp",
        "PQCsignKAT_SNOVA_25_8_3_ESK.rsp",
        "PQCsignKAT_SNOVA_25_8_3_SHAKE_ESK.rsp",
        "PQCsignKAT_SNOVA_25_8_3_SHAKE_SSK.rsp",
        "PQCsignKAT_SNOVA_25_8_3_SSK.rsp",
        "PQCsignKAT_SNOVA_29_6_5_ESK.rsp",
        "PQCsignKAT_SNOVA_29_6_5_SHAKE_ESK.rsp",
        "PQCsignKAT_SNOVA_29_6_5_SHAKE_SSK.rsp",
        "PQCsignKAT_SNOVA_29_6_5_SSK.rsp",
        "PQCsignKAT_SNOVA_37_8_4_ESK.rsp",
        "PQCsignKAT_SNOVA_37_8_4_SHAKE_ESK.rsp",
        "PQCsignKAT_SNOVA_37_8_4_SHAKE_SSK.rsp",
        "PQCsignKAT_SNOVA_37_8_4_SSK.rsp",
        "PQCsignKAT_SNOVA_37_17_2_ESK.rsp",
        "PQCsignKAT_SNOVA_37_17_2_SHAKE_ESK.rsp",
        "PQCsignKAT_SNOVA_37_17_2_SHAKE_SSK.rsp",
        "PQCsignKAT_SNOVA_37_17_2_SSK.rsp",
        "PQCsignKAT_SNOVA_49_11_3_ESK.rsp",
        "PQCsignKAT_SNOVA_49_11_3_SHAKE_ESK.rsp",
        "PQCsignKAT_SNOVA_49_11_3_SHAKE_SSK.rsp",
        "PQCsignKAT_SNOVA_49_11_3_SSK.rsp",
        "PQCsignKAT_SNOVA_56_25_2_ESK.rsp",
        "PQCsignKAT_SNOVA_56_25_2_SHAKE_ESK.rsp",
        "PQCsignKAT_SNOVA_56_25_2_SHAKE_SSK.rsp",
        "PQCsignKAT_SNOVA_56_25_2_SSK.rsp",
        "PQCsignKAT_SNOVA_60_10_4_ESK.rsp",
        "PQCsignKAT_SNOVA_60_10_4_SHAKE_ESK.rsp",
        "PQCsignKAT_SNOVA_60_10_4_SHAKE_SSK.rsp",
        "PQCsignKAT_SNOVA_60_10_4_SSK.rsp",
        "PQCsignKAT_SNOVA_66_15_3_ESK.rsp",
        "PQCsignKAT_SNOVA_66_15_3_SHAKE_ESK.rsp",
        "PQCsignKAT_SNOVA_66_15_3_SHAKE_SSK.rsp",
        "PQCsignKAT_SNOVA_66_15_3_SSK.rsp",
        "PQCsignKAT_SNOVA_75_33_2_ESK.rsp",
        "PQCsignKAT_SNOVA_75_33_2_SHAKE_ESK.rsp",
        "PQCsignKAT_SNOVA_75_33_2_SHAKE_SSK.rsp",
        "PQCsignKAT_SNOVA_75_33_2_SSK.rsp",
    };


    public void testTestVectors()
        throws Exception
    {
        long start = System.currentTimeMillis();
        TestUtils.testTestVector(true, true, false, "pqc/crypto/snova", files, new TestUtils.KeyGenerationOperation()
        {
            @Override
            public SecureRandom getSecureRandom(byte[] seed)
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
                return new SnovaSigner();
            }
        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }
}

