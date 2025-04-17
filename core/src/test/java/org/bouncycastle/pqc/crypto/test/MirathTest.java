package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.mirath.MirathKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mirath.MirathKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mirath.MirathParameters;
import org.bouncycastle.pqc.crypto.mirath.MirathPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mirath.MirathPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mirath.MirathSigner;

public class MirathTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        MirathTest test = new MirathTest();
        test.testTestVectors();
        //test.testKeyGen();
    }

    private static final MirathParameters[] PARAMETER_SETS = new MirathParameters[]
        {
            MirathParameters.mirath_1a_fast,
            MirathParameters.mirath_1a_short,
            MirathParameters.mirath_1b_fast,
            MirathParameters.mirath_1b_short,
            MirathParameters.mirath_3a_fast,
            MirathParameters.mirath_3a_short,
            MirathParameters.mirath_3b_fast,
            MirathParameters.mirath_3b_short,
            MirathParameters.mirath_5a_fast,
            MirathParameters.mirath_5a_short,
            MirathParameters.mirath_5b_fast,
            MirathParameters.mirath_5b_short
        };

    private static final String[] files = new String[]{
        "Mirath-1a-fast/PQCsignKAT_32.rsp",
        "Mirath-1a-short/PQCsignKAT_32.rsp",
        "Mirath-1b-fast/PQCsignKAT_32.rsp",
        "Mirath-1b-short/PQCsignKAT_32.rsp",
        "Mirath-3a-fast/PQCsignKAT_48.rsp",
        "Mirath-3a-short/PQCsignKAT_48.rsp",
        "Mirath-3b-fast/PQCsignKAT_48.rsp",
        "Mirath-3b-short/PQCsignKAT_48.rsp",
        "Mirath-5a-fast/PQCsignKAT_64.rsp",
        "Mirath-5a-short/PQCsignKAT_64.rsp",
        "Mirath-5b-fast/PQCsignKAT_64.rsp",
        "Mirath-5b-short/PQCsignKAT_64.rsp",
    };


    public void testTestVectors()
        throws Exception
    {
        long start = System.currentTimeMillis();
        TestUtils.testTestVector(false, false, "pqc/crypto/mirath", files, new TestUtils.KeyGenerationOperation()
        {
            @Override
            public SecureRandom getSecureRanom(byte[] seed)
            {
                return new NISTSecureRandom(seed, null);
            }

            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
                MirathParameters parameters = PARAMETER_SETS[fileIndex];

                MirathKeyPairGenerator kpGen = new MirathKeyPairGenerator();
                kpGen.init(new MirathKeyGenerationParameters(random, parameters));
                return kpGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams)
            {
                return ((MirathPublicKeyParameters)pubParams).getEncoded();
            }

            @Override
            public byte[] getPrivateKeyEncoded(CipherParameters privParams)
            {
                return ((MirathPrivateKeyParameters)privParams).getEncoded();
            }

            @Override
            public Signer getSigner()
            {
                return null;
            }

            @Override
            public MessageSigner getMessageSigner()
            {
                return new MirathSigner();
            }
        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }
}