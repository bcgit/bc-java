package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.aimer.AIMerKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerKeyPairGenerator;
import org.bouncycastle.pqc.crypto.aimer.AIMerParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerPublicKeyParameters;
import org.bouncycastle.pqc.crypto.aimer.AIMerSigner;

public class AIMerTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        AIMerTest test = new AIMerTest();
        test.testTestVectors();
    }

    private static final AIMerParameters[] PARAMETER_SETS = new AIMerParameters[]
        {
            AIMerParameters.aimer128f,
            AIMerParameters.aimer128s,
            AIMerParameters.aimer192f,
            AIMerParameters.aimer192s,
            AIMerParameters.aimer256f,
            AIMerParameters.aimer256s,
        };

    private static final String[] files = new String[]{
        "aimer128f/PQCsignKAT_48.rsp",
        "aimer128s/PQCsignKAT_48.rsp",
        "aimer192f/PQCsignKAT_72.rsp",
        "aimer192s/PQCsignKAT_72.rsp",
        "aimer256f/PQCsignKAT_96.rsp",
        "aimer256s/PQCsignKAT_96.rsp",
    };


    public void testTestVectors()
        throws Exception
    {
        long start = System.currentTimeMillis();
        TestUtils.testTestVector(false, true, false, "pqc/crypto/aimer", files, new TestUtils.SignerOperation()
        {
            @Override
            public SecureRandom getSecureRandom(byte[] seed)
            {
                return new NISTSecureRandom(seed, null);
            }

            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
                AIMerParameters parameters = PARAMETER_SETS[fileIndex];

                AIMerKeyPairGenerator kpGen = new AIMerKeyPairGenerator();
                kpGen.init(new AIMerKeyGenerationParameters(random, parameters));
                return kpGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(CipherParameters pubParams)
            {
                return ((AIMerPublicKeyParameters)pubParams).getEncoded();
            }

            @Override
            public byte[] getPrivateKeyEncoded(CipherParameters privParams)
            {
                return ((AIMerPrivateKeyParameters)privParams).getEncoded();
            }

            @Override
            public Signer getSigner()
            {
                return null;
            }

            @Override
            public MessageSigner getMessageSigner()
            {
                return new AIMerSigner();
            }
        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }
}
