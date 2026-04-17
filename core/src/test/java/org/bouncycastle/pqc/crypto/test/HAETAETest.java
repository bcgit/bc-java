package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.haetae.HAETAEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.haetae.HAETAEParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAESigner;

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
        TestUtils.testTestVector(false, false, false, "pqc/crypto/haetae", files, new TestUtils.SignerOperation()
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
            public byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams)
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
        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) +"\n");
    }
}
