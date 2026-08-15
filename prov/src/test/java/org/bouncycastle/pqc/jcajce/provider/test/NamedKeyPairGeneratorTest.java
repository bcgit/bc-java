package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.interfaces.CMCEKey;
import org.bouncycastle.jcajce.interfaces.FrodoKEMKey;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;
import org.bouncycastle.jcajce.interfaces.MLKEMKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAKey;
import org.bouncycastle.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.AIMerKey;
import org.bouncycastle.pqc.jcajce.interfaces.FaestKey;
import org.bouncycastle.pqc.jcajce.interfaces.FalconKey;
import org.bouncycastle.pqc.jcajce.interfaces.HQCKey;
import org.bouncycastle.pqc.jcajce.interfaces.HaetaeKey;
import org.bouncycastle.pqc.jcajce.interfaces.MQOMKey;
import org.bouncycastle.pqc.jcajce.interfaces.MayoKey;
import org.bouncycastle.pqc.jcajce.interfaces.NTRUPlusKey;
import org.bouncycastle.pqc.jcajce.interfaces.QRUOVKey;
import org.bouncycastle.pqc.jcajce.interfaces.SDitHKey;
import org.bouncycastle.pqc.jcajce.interfaces.SQIsignKey;
import org.bouncycastle.pqc.jcajce.interfaces.SmaugTKey;
import org.bouncycastle.pqc.jcajce.interfaces.SnovaKey;
import org.bouncycastle.pqc.jcajce.interfaces.UOVKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.AIMerParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FaestParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.HaetaeParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.MQOMParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.MayoParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRUPlusParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.QRUOVParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SDitHParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SQIsignParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SmaugTParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SnovaParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.UOVParameterSpec;

/**
 * Completeness check over every PQC algorithm family that registers parameter-set specific
 * KeyPairGenerators, in either the BC or the BCPQC provider.
 * <p>
 * Two properties are asserted for each such generator, both of which have been wrong in the past
 * (see the 1.86 release notes): an <b>uninitialised</b> generator obtained by parameter set name
 * must generate for that parameter set rather than for its family's default, and an attempt to
 * <b>re-point</b> it at a different parameter set through initialize(AlgorithmParameterSpec, ...)
 * must be refused rather than quietly honoured. A family whose generator silently substitutes its
 * default hands a caller keys at a security level it did not ask for.
 * <p>
 * The per-family tests elsewhere in this package cover their own families in more depth; this test
 * exists so that a family added later cannot be left out of that coverage unnoticed. Each family
 * lists all of its parameter sets. The lock check runs over every one of them, being free - it
 * throws before any key is generated. The default check needs a key pair per parameter set, so for
 * the families whose keygen is expensive it samples every n-th set (the {@code stride} column,
 * 1 = every set); the sampled sets are spread across security levels and variants rather than
 * clustered.
 * <p>
 * Every family with named generators is listed. The pre-standardisation SPHINCS+ and Kyber
 * provider classes, which neither provider had registered since they were superseded by SLH-DSA
 * and ML-KEM, were removed in 1.86 rather than covered here.
 */
public class NamedKeyPairGeneratorTest
    extends TestCase
{
    private static class Family
    {
        final String label;
        final String provider;
        final int stride;
        final AlgorithmParameterSpec[] specs;
        final String[] algNames;

        Family(String label, String provider, int stride, AlgorithmParameterSpec[] specs, String[] algNames)
        {
            this.label = label;
            this.provider = provider;
            this.stride = stride;
            this.specs = specs;
            this.algNames = algNames;
        }

        String algName(int i)
            throws Exception
        {
            return algNames != null ? algNames[i] : specName(specs[i]);
        }
    }

    private static Family[] families()
    {
        return new Family[]
        {
            new Family("SLH-DSA", "BC", 3,
                new AlgorithmParameterSpec[]
                {
                    SLHDSAParameterSpec.slh_dsa_sha2_128f,
                    SLHDSAParameterSpec.slh_dsa_sha2_128s,
                    SLHDSAParameterSpec.slh_dsa_sha2_192f,
                    SLHDSAParameterSpec.slh_dsa_sha2_192s,
                    SLHDSAParameterSpec.slh_dsa_sha2_256f,
                    SLHDSAParameterSpec.slh_dsa_sha2_256s,
                    SLHDSAParameterSpec.slh_dsa_shake_128f,
                    SLHDSAParameterSpec.slh_dsa_shake_128s,
                    SLHDSAParameterSpec.slh_dsa_shake_192f,
                    SLHDSAParameterSpec.slh_dsa_shake_192s,
                    SLHDSAParameterSpec.slh_dsa_shake_256f,
                    SLHDSAParameterSpec.slh_dsa_shake_256s,
                    SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256,
                    SLHDSAParameterSpec.slh_dsa_sha2_128s_with_sha256,
                    SLHDSAParameterSpec.slh_dsa_sha2_192f_with_sha512,
                    SLHDSAParameterSpec.slh_dsa_sha2_192s_with_sha512,
                    SLHDSAParameterSpec.slh_dsa_sha2_256f_with_sha512,
                    SLHDSAParameterSpec.slh_dsa_sha2_256s_with_sha512,
                    SLHDSAParameterSpec.slh_dsa_shake_128f_with_shake128,
                    SLHDSAParameterSpec.slh_dsa_shake_128s_with_shake128,
                    SLHDSAParameterSpec.slh_dsa_shake_192f_with_shake256,
                    SLHDSAParameterSpec.slh_dsa_shake_192s_with_shake256,
                    SLHDSAParameterSpec.slh_dsa_shake_256f_with_shake256,
                    SLHDSAParameterSpec.slh_dsa_shake_256s_with_shake256
                },
                null),
            new Family("ML-DSA", "BC", 1,
                new AlgorithmParameterSpec[]
                {
                    MLDSAParameterSpec.ml_dsa_44,
                    MLDSAParameterSpec.ml_dsa_65,
                    MLDSAParameterSpec.ml_dsa_87,
                    MLDSAParameterSpec.ml_dsa_44_with_sha512,
                    MLDSAParameterSpec.ml_dsa_65_with_sha512,
                    MLDSAParameterSpec.ml_dsa_87_with_sha512
                },
                null),
            new Family("ML-KEM", "BC", 1,
                new AlgorithmParameterSpec[]
                {
                    MLKEMParameterSpec.ml_kem_512,
                    MLKEMParameterSpec.ml_kem_768,
                    MLKEMParameterSpec.ml_kem_1024
                },
                null),
            new Family("Classic McEliece", "BC", 4,
                new AlgorithmParameterSpec[]
                {
                    CMCEParameterSpec.mceliece460896,
                    CMCEParameterSpec.mceliece460896f,
                    CMCEParameterSpec.mceliece460896pc,
                    CMCEParameterSpec.mceliece460896pcf,
                    CMCEParameterSpec.mceliece6688128,
                    CMCEParameterSpec.mceliece6688128f,
                    CMCEParameterSpec.mceliece6688128pc,
                    CMCEParameterSpec.mceliece6688128pcf,
                    CMCEParameterSpec.mceliece6960119,
                    CMCEParameterSpec.mceliece6960119f,
                    CMCEParameterSpec.mceliece6960119pc,
                    CMCEParameterSpec.mceliece6960119pcf,
                    CMCEParameterSpec.mceliece8192128,
                    CMCEParameterSpec.mceliece8192128f,
                    CMCEParameterSpec.mceliece8192128pc,
                    CMCEParameterSpec.mceliece8192128pcf
                },
                null),
            new Family("FrodoKEM", "BC", 1,
                new AlgorithmParameterSpec[]
                {
                    FrodoKEMParameterSpec.frodokem976shake,
                    FrodoKEMParameterSpec.frodokem1344shake,
                    FrodoKEMParameterSpec.efrodokem976shake,
                    FrodoKEMParameterSpec.efrodokem1344shake,
                    FrodoKEMParameterSpec.frodokem976aes,
                    FrodoKEMParameterSpec.frodokem1344aes,
                    FrodoKEMParameterSpec.efrodokem976aes,
                    FrodoKEMParameterSpec.efrodokem1344aes
                },
                null),
            new Family("QRUOV", "BCPQC", 4,
                new AlgorithmParameterSpec[]
                {
                    QRUOVParameterSpec.qruov1q127L3v156m54,
                    QRUOVParameterSpec.qruov1q31L3v165m60,
                    QRUOVParameterSpec.qruov1q31L10v600m70,
                    QRUOVParameterSpec.qruov1q7L10v740m100,
                    QRUOVParameterSpec.qruov3q127L3v228m78,
                    QRUOVParameterSpec.qruov3q31L3v246m87,
                    QRUOVParameterSpec.qruov3q31L10v890m100,
                    QRUOVParameterSpec.qruov3q7L10v1100m140,
                    QRUOVParameterSpec.qruov5q127L3v306m105,
                    QRUOVParameterSpec.qruov5q31L3v324m114,
                    QRUOVParameterSpec.qruov5q31L10v1120m120,
                    QRUOVParameterSpec.qruov5q7L10v1490m190
                },
                null),
            new Family("FAEST", "BCPQC", 1,
                new AlgorithmParameterSpec[]
                {
                    FaestParameterSpec.faest_128s,
                    FaestParameterSpec.faest_128f,
                    FaestParameterSpec.faest_192s,
                    FaestParameterSpec.faest_192f,
                    FaestParameterSpec.faest_256s,
                    FaestParameterSpec.faest_256f,
                    FaestParameterSpec.faest_em_128s,
                    FaestParameterSpec.faest_em_128f,
                    FaestParameterSpec.faest_em_192s,
                    FaestParameterSpec.faest_em_192f,
                    FaestParameterSpec.faest_em_256s,
                    FaestParameterSpec.faest_em_256f
                },
                null),
            new Family("HAETAE", "BCPQC", 1,
                new AlgorithmParameterSpec[]
                {
                    HaetaeParameterSpec.haetae2,
                    HaetaeParameterSpec.haetae3,
                    HaetaeParameterSpec.haetae5
                },
                null),
            new Family("SDitH", "BCPQC", 1,
                new AlgorithmParameterSpec[]
                {
                    SDitHParameterSpec.sdith_hypercube_cat1_gf256,
                    SDitHParameterSpec.sdith_hypercube_cat3_gf256,
                    SDitHParameterSpec.sdith_hypercube_cat5_gf256,
                    SDitHParameterSpec.sdith_hypercube_cat1_p251,
                    SDitHParameterSpec.sdith_hypercube_cat3_p251,
                    SDitHParameterSpec.sdith_hypercube_cat5_p251,
                    SDitHParameterSpec.sdith_threshold_cat1_gf256,
                    SDitHParameterSpec.sdith_threshold_cat3_gf256,
                    SDitHParameterSpec.sdith_threshold_cat5_gf256,
                    SDitHParameterSpec.sdith_threshold_cat1_p251,
                    SDitHParameterSpec.sdith_threshold_cat3_p251,
                    SDitHParameterSpec.sdith_threshold_cat5_p251
                },
                null),
            new Family("MQOM", "BCPQC", 3,
                new AlgorithmParameterSpec[]
                {
                    MQOMParameterSpec.mqom2_cat1_gf2_fast_r3,
                    MQOMParameterSpec.mqom2_cat1_gf2_fast_r5,
                    MQOMParameterSpec.mqom2_cat1_gf2_short_r3,
                    MQOMParameterSpec.mqom2_cat1_gf2_short_r5,
                    MQOMParameterSpec.mqom2_cat1_gf16_fast_r3,
                    MQOMParameterSpec.mqom2_cat1_gf16_fast_r5,
                    MQOMParameterSpec.mqom2_cat1_gf16_short_r3,
                    MQOMParameterSpec.mqom2_cat1_gf16_short_r5,
                    MQOMParameterSpec.mqom2_cat1_gf256_fast_r3,
                    MQOMParameterSpec.mqom2_cat1_gf256_fast_r5,
                    MQOMParameterSpec.mqom2_cat1_gf256_short_r3,
                    MQOMParameterSpec.mqom2_cat1_gf256_short_r5,
                    MQOMParameterSpec.mqom2_cat3_gf2_fast_r3,
                    MQOMParameterSpec.mqom2_cat3_gf2_fast_r5,
                    MQOMParameterSpec.mqom2_cat3_gf2_short_r3,
                    MQOMParameterSpec.mqom2_cat3_gf2_short_r5,
                    MQOMParameterSpec.mqom2_cat3_gf16_fast_r3,
                    MQOMParameterSpec.mqom2_cat3_gf16_fast_r5,
                    MQOMParameterSpec.mqom2_cat3_gf16_short_r3,
                    MQOMParameterSpec.mqom2_cat3_gf16_short_r5,
                    MQOMParameterSpec.mqom2_cat3_gf256_fast_r3,
                    MQOMParameterSpec.mqom2_cat3_gf256_fast_r5,
                    MQOMParameterSpec.mqom2_cat3_gf256_short_r3,
                    MQOMParameterSpec.mqom2_cat3_gf256_short_r5,
                    MQOMParameterSpec.mqom2_cat5_gf2_fast_r3,
                    MQOMParameterSpec.mqom2_cat5_gf2_fast_r5,
                    MQOMParameterSpec.mqom2_cat5_gf2_short_r3,
                    MQOMParameterSpec.mqom2_cat5_gf2_short_r5,
                    MQOMParameterSpec.mqom2_cat5_gf16_fast_r3,
                    MQOMParameterSpec.mqom2_cat5_gf16_fast_r5,
                    MQOMParameterSpec.mqom2_cat5_gf16_short_r3,
                    MQOMParameterSpec.mqom2_cat5_gf16_short_r5,
                    MQOMParameterSpec.mqom2_cat5_gf256_fast_r3,
                    MQOMParameterSpec.mqom2_cat5_gf256_fast_r5,
                    MQOMParameterSpec.mqom2_cat5_gf256_short_r3,
                    MQOMParameterSpec.mqom2_cat5_gf256_short_r5
                },
                null),
            new Family("UOV", "BCPQC", 3,
                new AlgorithmParameterSpec[]
                {
                    UOVParameterSpec.uov_Is,
                    UOVParameterSpec.uov_Is_pkc,
                    UOVParameterSpec.uov_Is_pkc_skc,
                    UOVParameterSpec.uov_Ip,
                    UOVParameterSpec.uov_Ip_pkc,
                    UOVParameterSpec.uov_Ip_pkc_skc,
                    UOVParameterSpec.uov_III,
                    UOVParameterSpec.uov_III_pkc,
                    UOVParameterSpec.uov_III_pkc_skc,
                    UOVParameterSpec.uov_V,
                    UOVParameterSpec.uov_V_pkc,
                    UOVParameterSpec.uov_V_pkc_skc
                },
                null),
            new Family("SMAUG-T", "BCPQC", 1,
                new AlgorithmParameterSpec[]
                {
                    SmaugTParameterSpec.smaugt_mode1,
                    SmaugTParameterSpec.smaugt_mode3,
                    SmaugTParameterSpec.smaugt_mode5,
                    SmaugTParameterSpec.smaugt_modet
                },
                new String[]
                {
                    "SMAUGT-MODE1",
                    "SMAUGT-MODE3",
                    "SMAUGT-MODE5",
                    "SMAUGT-MODET"
                }),
            new Family("Falcon", "BCPQC", 1,
                new AlgorithmParameterSpec[]
                {
                    FalconParameterSpec.falcon_512,
                    FalconParameterSpec.falcon_1024
                },
                null),
            new Family("NTRU+", "BCPQC", 1,
                new AlgorithmParameterSpec[]
                {
                    NTRUPlusParameterSpec.ntruplus_768,
                    NTRUPlusParameterSpec.ntruplus_864,
                    NTRUPlusParameterSpec.ntruplus_1152
                },
null),
            new Family("HQC", "BCPQC", 1,
                new AlgorithmParameterSpec[]
                {
                    HQCParameterSpec.hqc128,
                    HQCParameterSpec.hqc192,
                    HQCParameterSpec.hqc256
                },
                null),
            new Family("MAYO", "BCPQC", 1,
                new AlgorithmParameterSpec[]
                {
                    MayoParameterSpec.mayo1,
                    MayoParameterSpec.mayo2,
                    MayoParameterSpec.mayo3,
                    MayoParameterSpec.mayo5
                },
                null),
            new Family("AIMer", "BCPQC", 1,
                new AlgorithmParameterSpec[]
                {
                    AIMerParameterSpec.aimer128f,
                    AIMerParameterSpec.aimer128s,
                    AIMerParameterSpec.aimer192f,
                    AIMerParameterSpec.aimer192s,
                    AIMerParameterSpec.aimer256f,
                    AIMerParameterSpec.aimer256s
                },
                new String[]
                {
                    "AIMer-128f",
                    "AIMer-128s",
                    "AIMer-192f",
                    "AIMer-192s",
                    "AIMer-256f",
                    "AIMer-256s"
                }),
            new Family("SQIsign", "BCPQC", 1,
                new AlgorithmParameterSpec[]
                {
                    SQIsignParameterSpec.sqisign_lvl1,
                    SQIsignParameterSpec.sqisign_lvl3,
                    SQIsignParameterSpec.sqisign_lvl5
                },
                null),
            new Family("SNOVA", "BCPQC", 6,
                new AlgorithmParameterSpec[]
                {
                    SnovaParameterSpec.SNOVA_24_5_4_SSK,
                    SnovaParameterSpec.SNOVA_24_5_4_ESK,
                    SnovaParameterSpec.SNOVA_24_5_4_SHAKE_SSK,
                    SnovaParameterSpec.SNOVA_24_5_4_SHAKE_ESK,
                    SnovaParameterSpec.SNOVA_24_5_5_SSK,
                    SnovaParameterSpec.SNOVA_24_5_5_ESK,
                    SnovaParameterSpec.SNOVA_24_5_5_SHAKE_SSK,
                    SnovaParameterSpec.SNOVA_24_5_5_SHAKE_ESK,
                    SnovaParameterSpec.SNOVA_25_8_3_SSK,
                    SnovaParameterSpec.SNOVA_25_8_3_ESK,
                    SnovaParameterSpec.SNOVA_25_8_3_SHAKE_SSK,
                    SnovaParameterSpec.SNOVA_25_8_3_SHAKE_ESK,
                    SnovaParameterSpec.SNOVA_29_6_5_SSK,
                    SnovaParameterSpec.SNOVA_29_6_5_ESK,
                    SnovaParameterSpec.SNOVA_29_6_5_SHAKE_SSK,
                    SnovaParameterSpec.SNOVA_29_6_5_SHAKE_ESK,
                    SnovaParameterSpec.SNOVA_37_8_4_SSK,
                    SnovaParameterSpec.SNOVA_37_8_4_ESK,
                    SnovaParameterSpec.SNOVA_37_8_4_SHAKE_SSK,
                    SnovaParameterSpec.SNOVA_37_8_4_SHAKE_ESK,
                    SnovaParameterSpec.SNOVA_37_17_2_SSK,
                    SnovaParameterSpec.SNOVA_37_17_2_ESK,
                    SnovaParameterSpec.SNOVA_37_17_2_SHAKE_SSK,
                    SnovaParameterSpec.SNOVA_37_17_2_SHAKE_ESK,
                    SnovaParameterSpec.SNOVA_49_11_3_SSK,
                    SnovaParameterSpec.SNOVA_49_11_3_ESK,
                    SnovaParameterSpec.SNOVA_49_11_3_SHAKE_SSK,
                    SnovaParameterSpec.SNOVA_49_11_3_SHAKE_ESK,
                    SnovaParameterSpec.SNOVA_56_25_2_SSK,
                    SnovaParameterSpec.SNOVA_56_25_2_ESK,
                    SnovaParameterSpec.SNOVA_56_25_2_SHAKE_SSK,
                    SnovaParameterSpec.SNOVA_56_25_2_SHAKE_ESK,
                    SnovaParameterSpec.SNOVA_60_10_4_SSK,
                    SnovaParameterSpec.SNOVA_60_10_4_ESK,
                    SnovaParameterSpec.SNOVA_60_10_4_SHAKE_SSK,
                    SnovaParameterSpec.SNOVA_60_10_4_SHAKE_ESK,
                    SnovaParameterSpec.SNOVA_66_15_3_SSK,
                    SnovaParameterSpec.SNOVA_66_15_3_ESK,
                    SnovaParameterSpec.SNOVA_66_15_3_SHAKE_SSK,
                    SnovaParameterSpec.SNOVA_66_15_3_SHAKE_ESK,
                    SnovaParameterSpec.SNOVA_75_33_2_SSK,
                    SnovaParameterSpec.SNOVA_75_33_2_ESK,
                    SnovaParameterSpec.SNOVA_75_33_2_SHAKE_SSK,
                    SnovaParameterSpec.SNOVA_75_33_2_SHAKE_ESK
                },
                null),
        };
    }

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testNamedGeneratorDefaultsToItsParameterSet()
        throws Exception
    {
        Family[] families = families();

        for (int f = 0; f != families.length; f++)
        {
            Family fam = families[f];

            for (int i = 0; i < fam.specs.length; i += fam.stride)
            {
                String expected = specName(fam.specs[i]);
                String algName = fam.algName(i);

                KeyPairGenerator kpg = KeyPairGenerator.getInstance(algName, fam.provider);

                KeyPair kp = kpg.generateKeyPair();

                assertEquals(fam.label + " " + algName, expected, paramSetName(kp.getPublic()));
                assertEquals(fam.label + " " + algName, expected, paramSetName(kp.getPrivate()));
            }
        }
    }

    public void testNamedGeneratorLockedToItsParameterSet()
        throws Exception
    {
        Family[] families = families();

        for (int f = 0; f != families.length; f++)
        {
            Family fam = families[f];

            for (int i = 0; i != fam.specs.length; i++)
            {
                String algName = fam.algName(i);

                AlgorithmParameterSpec other = fam.specs[i == 0 ? 1 : 0];

                KeyPairGenerator kpg = KeyPairGenerator.getInstance(algName, fam.provider);

                try
                {
                    kpg.initialize(other, new SecureRandom());
                    fail(fam.label + " " + algName + ": no exception");
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    assertTrue(fam.label + " " + algName + ": " + e.getMessage(),
                        e.getMessage().startsWith("key pair generator locked to "));
                }

                kpg.initialize(fam.specs[i], new SecureRandom());
            }
        }
    }

    /**
     * getInstance(spec.getName()) is the natural idiom for turning a parameter set into a
     * generator, and every family supports it - three of them (AIMer, SMAUG-T and NTRU+) only
     * because their parameter set spelling is registered as an alias of the hyphenated algorithm
     * name. Resolution is all that is asserted here; that the resolved generator then behaves is
     * covered by the two tests above, which drive the canonical names.
     */
    public void testParameterSetNameResolves()
        throws Exception
    {
        Family[] families = families();

        for (int f = 0; f != families.length; f++)
        {
            Family fam = families[f];

            for (int i = 0; i != fam.specs.length; i++)
            {
                String specName = specName(fam.specs[i]);

                KeyPairGenerator kpg = KeyPairGenerator.getInstance(specName, fam.provider);

                assertNotNull(fam.label + " " + specName, kpg);
            }
        }
    }

    private static String specName(AlgorithmParameterSpec spec)
        throws Exception
    {
        return (String)spec.getClass().getMethod("getName").invoke(spec);
    }

    /**
     * The parameter set a generated key actually belongs to. Deliberately exhaustive rather than
     * reflective: a family added without a branch here fails loudly instead of being skipped.
     */
    private static String paramSetName(Key key)
    {
        if (key instanceof SLHDSAKey)
        {
            return ((SLHDSAKey)key).getParameterSpec().getName();
        }
        if (key instanceof MLDSAKey)
        {
            return ((MLDSAKey)key).getParameterSpec().getName();
        }
        if (key instanceof MLKEMKey)
        {
            return ((MLKEMKey)key).getParameterSpec().getName();
        }
        if (key instanceof CMCEKey)
        {
            return ((CMCEKey)key).getParameterSpec().getName();
        }
        if (key instanceof FrodoKEMKey)
        {
            return ((FrodoKEMKey)key).getParameterSpec().getName();
        }
        if (key instanceof QRUOVKey)
        {
            return ((QRUOVKey)key).getParameterSpec().getName();
        }
        if (key instanceof FaestKey)
        {
            return ((FaestKey)key).getParameterSpec().getName();
        }
        if (key instanceof HaetaeKey)
        {
            return ((HaetaeKey)key).getParameterSpec().getName();
        }
        if (key instanceof SDitHKey)
        {
            return ((SDitHKey)key).getParameterSpec().getName();
        }
        if (key instanceof MQOMKey)
        {
            return ((MQOMKey)key).getParameterSpec().getName();
        }
        if (key instanceof UOVKey)
        {
            return ((UOVKey)key).getParameterSpec().getName();
        }
        if (key instanceof SmaugTKey)
        {
            return ((SmaugTKey)key).getParameterSpec().getName();
        }
        if (key instanceof FalconKey)
        {
            return ((FalconKey)key).getParameterSpec().getName();
        }
        if (key instanceof NTRUPlusKey)
        {
            return ((NTRUPlusKey)key).getParameterSpec().getName();
        }
        if (key instanceof HQCKey)
        {
            return ((HQCKey)key).getParameterSpec().getName();
        }
        if (key instanceof MayoKey)
        {
            return ((MayoKey)key).getParameterSpec().getName();
        }
        if (key instanceof AIMerKey)
        {
            return ((AIMerKey)key).getParameterSpec().getName();
        }
        if (key instanceof SQIsignKey)
        {
            return ((SQIsignKey)key).getParameterSpec().getName();
        }
        if (key instanceof SnovaKey)
        {
            return ((SnovaKey)key).getParameterSpec().getName();
        }

        throw new IllegalStateException("no parameter set accessor for " + key.getClass().getName());
    }
}
