package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.haetae.HAETAEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.haetae.HAETAEParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAESigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.FixedSecureRandom;

public class HAETAETest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        HAETAETest test = new HAETAETest();
        test.testTestVectors();
        //test.testKeyGen();
    }

    private static final HAETAEParameters[] PARAMETER_SETS = new HAETAEParameters[]
        {
            HAETAEParameters.haetae2,
            HAETAEParameters.haetae3,
            HAETAEParameters.haetae5,
        };

    private static final String[] files = new String[]{
        "PQCsignKAT_haetae_mode2.rsp",
        "PQCsignKAT_haetae_mode3.rsp",
        "PQCsignKAT_haetae_mode5.rsp",
    };


    public void testTestVectors()
        throws Exception
    {
        long start = System.currentTimeMillis();
        TestUtils.testTestVector(true, false, false, "pqc/crypto/haetae", files, new TestUtils.SignerOperation()
        {
            @Override
            public SecureRandom getSecureRandom(byte[] seed)
            {
                return new NISTSecureRandom(seed, null);
            }

            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
                HAETAEParameters parameters = PARAMETER_SETS[fileIndex];

                HAETAEKeyPairGenerator kpGen = new HAETAEKeyPairGenerator();
                kpGen.init(new HAETAEKeyGenerationParameters(random, parameters));
                return kpGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(CipherParameters pubParams)
            {
                return ((HAETAEPublicKeyParameters)pubParams).getEncoded();
            }

            @Override
            public byte[] getPrivateKeyEncoded(CipherParameters privParams)
            {
                return ((HAETAEPrivateKeyParameters)privParams).getEncoded();
            }

            @Override
            public Signer getSigner()
            {
                return null;
            }

            @Override
            public MessageSigner getMessageSigner()
            {
                return new HAETAESigner();
            }

            @Override
            public CipherParameters setSignParameters(CipherParameters privParams, SecureRandom random)
            {
                byte[] rnd = new byte[32];
                byte[] ctx = new byte[1];
                random.nextBytes(rnd);
                random.nextBytes(ctx);
                byte[] pre = new byte[(ctx[0] & 0xff)];
                random.nextBytes(pre);
                random = new FixedSecureRandom(rnd);
                return new ParametersWithContext(new ParametersWithRandom(privParams, random), Arrays.concatenate(ctx, pre));
            }

            @Override
            public CipherParameters setVerifyParameters(CipherParameters pubParams, CipherParameters privParams)
            {
                byte[] pre = ((ParametersWithContext)privParams).getContext();
                return new ParametersWithContext(pubParams, pre);
            }
        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }
}
