package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.snova.SnovaKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaKeyPairGenerator;
import org.bouncycastle.pqc.crypto.snova.SnovaParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaPublicKeyParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaSigner;
import org.bouncycastle.util.Arrays;


public class SnovaTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        SnovaTest test = new SnovaTest();
        test.testTestVectorsESK();
        test.testTestVectorsSSK();
        test.testTestVectorsShakeESK();
        test.testTestVectorsShakeSSK();
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


    // The KATs are split by secret key form (expanded ESK / seed SSK) and hash (SHAKE or not)
    // into four methods, each run from its own AllTestsSnova* suite so they can run as
    // separate (parallel) forks.
    public void testTestVectorsESK()
        throws Exception
    {
        runKats("_ESK.rsp", false);
    }

    public void testTestVectorsSSK()
        throws Exception
    {
        runKats("_SSK.rsp", false);
    }

    public void testTestVectorsShakeESK()
        throws Exception
    {
        runKats("_SHAKE_ESK.rsp", true);
    }

    public void testTestVectorsShakeSSK()
        throws Exception
    {
        runKats("_SHAKE_SSK.rsp", true);
    }

    private static boolean selected(String file, String suffix, boolean shake)
    {
        return file.endsWith(suffix) && (file.indexOf("_SHAKE_") >= 0) == shake;
    }

    /**
     * Run the KAT files whose names end in the given suffix and do (or do not) name the SHAKE
     * variant.
     */
    private static void runKats(String suffix, boolean shake)
        throws Exception
    {
        int n = 0;
        for (int i = 0; i != files.length; i++)
        {
            if (selected(files[i], suffix, shake))
            {
                n++;
            }
        }
        final SnovaParameters[] paramSets = new SnovaParameters[n];
        String[] katFiles = new String[n];
        n = 0;
        for (int i = 0; i != files.length; i++)
        {
            if (selected(files[i], suffix, shake))
            {
                paramSets[n] = PARAMETER_SETS[i];
                katFiles[n++] = files[i];
            }
        }

        long start = System.currentTimeMillis();
        TestUtils.testTestVector(true, true, false, "pqc/crypto/snova", katFiles, new TestUtils.SignerOperation()
        {
            @Override
            public SecureRandom getSecureRandom(byte[] seed)
            {
                return new NISTSecureRandom(seed, null);
            }

            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
                SnovaParameters parameters = paramSets[fileIndex];

                SnovaKeyPairGenerator kpGen = new SnovaKeyPairGenerator();
                kpGen.init(new SnovaKeyGenerationParameters(random, parameters));
                return kpGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(CipherParameters pubParams)
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

            // the KAT files record the NIST crypto_sign "sm" envelope,
            // signature || message; the signer returns the bare signature.
            @Override
            public byte[] toVectorSignature(byte[] signature, byte[] message)
            {
                return Arrays.concatenate(signature, message);
            }
        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }
}

