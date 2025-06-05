package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.cross.CrossKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.cross.CrossKeyPairGenerator;
import org.bouncycastle.pqc.crypto.cross.CrossParameters;
import org.bouncycastle.pqc.crypto.cross.CrossPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.cross.CrossPublicKeyParameters;
import org.bouncycastle.pqc.crypto.cross.CrossSigner;
import org.bouncycastle.pqc.crypto.cross.CsprngSecureRandom;

public class CrossTest
{
    public static void main(String[] args)
        throws Exception
    {
        CrossTest test = new CrossTest();
        test.testTestVectors();
    }

    private static final CrossParameters[] PARAMETER_SETS = new CrossParameters[]
        {
//            CrossParameters.cross_rsdpg_1_small,
//            CrossParameters.cross_rsdpg_1_balanced,
//            CrossParameters.cross_rsdpg_1_fast,
            CrossParameters.cross_rsdp_1_small,
            CrossParameters.cross_rsdp_1_balanced,
            CrossParameters.cross_rsdp_1_fast,
            CrossParameters.cross_rsdpg_3_small,
            CrossParameters.cross_rsdpg_3_balanced,
            CrossParameters.cross_rsdpg_3_fast,
            CrossParameters.cross_rsdp_3_small,
            CrossParameters.cross_rsdp_3_balanced,
            CrossParameters.cross_rsdp_3_fast,
            CrossParameters.cross_rsdpg_5_small,
            CrossParameters.cross_rsdpg_5_balanced,
            CrossParameters.cross_rsdpg_5_fast,
            CrossParameters.cross_rsdp_5_small,
            CrossParameters.cross_rsdp_5_balanced,
            CrossParameters.cross_rsdp_5_fast,
        };

    private static final String[] files = new String[]{
//        "PQCsignKAT_54_8960.rsp",
//        "PQCsignKAT_54_9120.rsp",
//        "PQCsignKAT_54_11980.rsp",
        "PQCsignKAT_77_12432.rsp",
        "PQCsignKAT_77_13152.rsp",
        "PQCsignKAT_77_18432.rsp",
        "PQCsignKAT_83_20452.rsp",
        "PQCsignKAT_83_22464.rsp",
        "PQCsignKAT_83_26772.rsp",
        "PQCsignKAT_106_36454.rsp",
        "PQCsignKAT_106_40100.rsp",
        "PQCsignKAT_106_48102.rsp",
        "PQCsignKAT_115_28391.rsp",
        "PQCsignKAT_115_29853.rsp",
        "PQCsignKAT_115_41406.rsp",
        "PQCsignKAT_153_50818.rsp",
        "PQCsignKAT_153_53527.rsp",
        "PQCsignKAT_153_74590.rsp",
    };


    public void testTestVectors()
        throws Exception
    {
        long start = System.currentTimeMillis();
        final byte[] entropyInput = new byte[48];
        for (int i = 0; i < 48; ++i)
        {
            entropyInput[i] = (byte)i;
        }
        final CsprngSecureRandom random = new CsprngSecureRandom(entropyInput);
        TestUtils.testTestVector(false, false, false, "pqc/crypto/Cross", files, new TestUtils.KeyGenerationOperation()
        {
            @Override
            public SecureRandom getSecureRandom(byte[] seed)
            {
                return random;
            }

            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
                CrossParameters parameters = PARAMETER_SETS[fileIndex];

                CrossKeyPairGenerator kpGen = new CrossKeyPairGenerator();
                kpGen.init(new CrossKeyGenerationParameters(random, parameters));
                return kpGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams)
            {
                return ((CrossPublicKeyParameters)pubParams).getEncoded();
            }

            @Override
            public byte[] getPrivateKeyEncoded(CipherParameters privParams)
            {
                return ((CrossPrivateKeyParameters)privParams).getEncoded();
            }

            @Override
            public Signer getSigner()
            {
                return null;
            }

            @Override
            public MessageSigner getMessageSigner()
            {
                return new CrossSigner();
            }
        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }
}
