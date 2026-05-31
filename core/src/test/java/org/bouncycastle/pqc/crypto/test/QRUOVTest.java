package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.qruov.QRUOVKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVKeyPairGenerator;
import org.bouncycastle.pqc.crypto.qruov.QRUOVParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVSigner;

public class QRUOVTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        runKats(ALL_SHAKE_PARAMS, buildFilenames(ALL_PARAM_SET_DIRS, "kat_shake", "refs"), true);
        runKats(ALL_AES_PARAMS, buildFilenames(ALL_PARAM_SET_DIRS, "kat_aes", "refa"), false);
    }

    private static final String[] DEFAULT_PARAM_SET_DIRS = new String[]{
        "qruov1q127L3v156m54",
        "qruov1q31L3v165m60",
        "qruov3q127L3v228m78",
        "qruov3q31L3v246m87",
    };

    // Full list used when QRUOVTest is invoked from main() — all 12 parameter sets.
    private static final QRUOVParameters[] ALL_SHAKE_PARAMS = new QRUOVParameters[]{
        QRUOVParameters.qruov_1_q127_L3_v156_m54_shake,
        QRUOVParameters.qruov_1_q31_L3_v165_m60_shake,
        QRUOVParameters.qruov_1_q31_L10_v600_m70_shake,
        QRUOVParameters.qruov_1_q7_L10_v740_m100_shake,
        QRUOVParameters.qruov_3_q127_L3_v228_m78_shake,
        QRUOVParameters.qruov_3_q31_L3_v246_m87_shake,
        QRUOVParameters.qruov_3_q31_L10_v890_m100_shake,
        QRUOVParameters.qruov_3_q7_L10_v1100_m140_shake,
        QRUOVParameters.qruov_5_q127_L3_v306_m105_shake,
        QRUOVParameters.qruov_5_q31_L3_v324_m114_shake,
        QRUOVParameters.qruov_5_q31_L10_v1120_m120_shake,
        QRUOVParameters.qruov_5_q7_L10_v1490_m190_shake,
    };

    private static final QRUOVParameters[] ALL_AES_PARAMS = new QRUOVParameters[]{
        QRUOVParameters.qruov_1_q127_L3_v156_m54_aes,
        QRUOVParameters.qruov_1_q31_L3_v165_m60_aes,
        QRUOVParameters.qruov_1_q31_L10_v600_m70_aes,
        QRUOVParameters.qruov_1_q7_L10_v740_m100_aes,
        QRUOVParameters.qruov_3_q127_L3_v228_m78_aes,
        QRUOVParameters.qruov_3_q31_L3_v246_m87_aes,
        QRUOVParameters.qruov_3_q31_L10_v890_m100_aes,
        QRUOVParameters.qruov_3_q7_L10_v1100_m140_aes,
        QRUOVParameters.qruov_5_q127_L3_v306_m105_aes,
        QRUOVParameters.qruov_5_q31_L3_v324_m114_aes,
        QRUOVParameters.qruov_5_q31_L10_v1120_m120_aes,
        QRUOVParameters.qruov_5_q7_L10_v1490_m190_aes,
    };

    private static final String[] ALL_PARAM_SET_DIRS = new String[]{
        "qruov1q127L3v156m54",
        "qruov1q31L3v165m60",
        "qruov1q31L10v600m70",
        "qruov1q7L10v740m100",
        "qruov3q127L3v228m78",
        "qruov3q31L3v246m87",
        "qruov3q31L10v890m100",
        "qruov3q7L10v1100m140",
        "qruov5q127L3v306m105",
        "qruov5q31L3v324m114",
        "qruov5q31L10v1120m120",
        "qruov5q7L10v1490m190",
    };

    public void testTestVectorsShake()
        throws Exception
    {
        // SHAKE variant is OID-mapped, so round-trip the keys through
        // PublicKeyFactory / PrivateKeyFactory as a side-check.
        runKats(ALL_SHAKE_PARAMS, buildFilenames(ALL_PARAM_SET_DIRS, "kat_shake", "refs"), true);
    }

    public void testTestVectorsAes()
        throws Exception
    {
        // AES PRG variants are intentionally not OID-mapped (the canonical JCE
        // surface uses SHAKE), so we don't round-trip the keys through the factory.
        runKats(ALL_AES_PARAMS, buildFilenames(ALL_PARAM_SET_DIRS, "kat_aes", "refa"), false);
    }

    private static String[] buildFilenames(String[] dirs, String prgDir, String refDir)
    {
        String[] out = new String[dirs.length];
        for (int i = 0; i < dirs.length; i++)
        {
            String name = dirs[i];
            // KAT filename uses 32/48/64 depending on category derived from the name prefix.
            int kat = name.startsWith("qruov1") ? 32 : (name.startsWith("qruov3") ? 48 : 64);
            out[i] = prgDir + "/" + name + "/" + refDir + "/PQCsignKAT_" + kat + ".rsp";
        }
        return out;
    }

    private static void runKats(final QRUOVParameters[] paramSets, String[] files, boolean enableFactory)
        throws Exception
    {
        long start = System.currentTimeMillis();
        TestUtils.testTestVector(true, enableFactory, false, "pqc/crypto/qruov", files, new TestUtils.SignerOperation()
        {
            @Override
            public SecureRandom getSecureRandom(byte[] seed)
            {
                return new NISTSecureRandom(seed, null);
            }

            @Override
            public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
            {
                QRUOVKeyPairGenerator kpGen = new QRUOVKeyPairGenerator();
                kpGen.init(new QRUOVKeyGenerationParameters(random, paramSets[fileIndex]));
                return kpGen;
            }

            @Override
            public byte[] getPublicKeyEncoded(CipherParameters pubParams)
            {
                return ((QRUOVPublicKeyParameters)pubParams).getEncoded();
            }

            @Override
            public byte[] getPrivateKeyEncoded(CipherParameters privParams)
            {
                return ((QRUOVPrivateKeyParameters)privParams).getEncoded();
            }

            @Override
            public Signer getSigner()
            {
                return null;
            }

            @Override
            public MessageSigner getMessageSigner()
            {
                return new QRUOVSigner();
            }
        });
        long end = System.currentTimeMillis();
        System.out.println("time cost: " + (end - start) + "\n");
    }
}
