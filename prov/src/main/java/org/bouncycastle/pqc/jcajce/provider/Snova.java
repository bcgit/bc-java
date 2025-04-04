package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.snova.SnovaKeyFactorySpi;

public class Snova
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.snova.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.Snova", PREFIX + "SnovaKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "SNOVA_24_5_4_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_24_5_4_SSK", BCObjectIdentifiers.snova_24_5_4_ssk, new SnovaKeyFactorySpi.SNOVA_24_5_4_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_24_5_4_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_24_5_4_ESK", BCObjectIdentifiers.snova_24_5_4_esk, new SnovaKeyFactorySpi.SNOVA_24_5_4_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_24_5_4_SHAKE_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_24_5_4_SHAKE_SSK", BCObjectIdentifiers.snova_24_5_4_shake_ssk, new SnovaKeyFactorySpi.SNOVA_24_5_4_SHAKE_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_24_5_4_SHAKE_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_24_5_4_SHAKE_ESK", BCObjectIdentifiers.snova_24_5_4_shake_esk, new SnovaKeyFactorySpi.SNOVA_24_5_4_SHAKE_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_24_5_5_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_24_5_5_SSK", BCObjectIdentifiers.snova_24_5_5_ssk, new SnovaKeyFactorySpi.SNOVA_24_5_5_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_24_5_5_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_24_5_5_ESK", BCObjectIdentifiers.snova_24_5_5_esk, new SnovaKeyFactorySpi.SNOVA_24_5_5_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_24_5_5_SHAKE_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_24_5_5_SHAKE_SSK", BCObjectIdentifiers.snova_24_5_5_shake_ssk, new SnovaKeyFactorySpi.SNOVA_24_5_5_SHAKE_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_24_5_5_SHAKE_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_24_5_5_SHAKE_ESK", BCObjectIdentifiers.snova_24_5_5_shake_esk, new SnovaKeyFactorySpi.SNOVA_24_5_5_SHAKE_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_25_8_3_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_25_8_3_SSK", BCObjectIdentifiers.snova_25_8_3_ssk, new SnovaKeyFactorySpi.SNOVA_25_8_3_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_25_8_3_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_25_8_3_ESK", BCObjectIdentifiers.snova_25_8_3_esk, new SnovaKeyFactorySpi.SNOVA_25_8_3_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_25_8_3_SHAKE_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_25_8_3_SHAKE_SSK", BCObjectIdentifiers.snova_25_8_3_shake_ssk, new SnovaKeyFactorySpi.SNOVA_25_8_3_SHAKE_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_25_8_3_SHAKE_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_25_8_3_SHAKE_ESK", BCObjectIdentifiers.snova_25_8_3_shake_esk, new SnovaKeyFactorySpi.SNOVA_25_8_3_SHAKE_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_29_6_5_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_29_6_5_SSK", BCObjectIdentifiers.snova_29_6_5_ssk, new SnovaKeyFactorySpi.SNOVA_29_6_5_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_29_6_5_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_29_6_5_ESK", BCObjectIdentifiers.snova_29_6_5_esk, new SnovaKeyFactorySpi.SNOVA_29_6_5_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_29_6_5_SHAKE_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_29_6_5_SHAKE_SSK", BCObjectIdentifiers.snova_29_6_5_shake_ssk, new SnovaKeyFactorySpi.SNOVA_29_6_5_SHAKE_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_29_6_5_SHAKE_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_29_6_5_SHAKE_ESK", BCObjectIdentifiers.snova_29_6_5_shake_esk, new SnovaKeyFactorySpi.SNOVA_29_6_5_SHAKE_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_37_8_4_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_37_8_4_SSK", BCObjectIdentifiers.snova_37_8_4_ssk, new SnovaKeyFactorySpi.SNOVA_37_8_4_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_37_8_4_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_37_8_4_ESK", BCObjectIdentifiers.snova_37_8_4_esk, new SnovaKeyFactorySpi.SNOVA_37_8_4_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_37_8_4_SHAKE_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_37_8_4_SHAKE_SSK", BCObjectIdentifiers.snova_37_8_4_shake_ssk, new SnovaKeyFactorySpi.SNOVA_37_8_4_SHAKE_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_37_8_4_SHAKE_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_37_8_4_SHAKE_ESK", BCObjectIdentifiers.snova_37_8_4_shake_esk, new SnovaKeyFactorySpi.SNOVA_37_8_4_SHAKE_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_37_17_2_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_37_17_2_SSK", BCObjectIdentifiers.snova_37_17_2_ssk, new SnovaKeyFactorySpi.SNOVA_37_17_2_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_37_17_2_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_37_17_2_ESK", BCObjectIdentifiers.snova_37_17_2_esk, new SnovaKeyFactorySpi.SNOVA_37_17_2_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_37_17_2_SHAKE_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_37_17_2_SHAKE_SSK", BCObjectIdentifiers.snova_37_17_2_shake_ssk, new SnovaKeyFactorySpi.SNOVA_37_17_2_SHAKE_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_37_17_2_SHAKE_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_37_17_2_SHAKE_ESK", BCObjectIdentifiers.snova_37_17_2_shake_esk, new SnovaKeyFactorySpi.SNOVA_37_17_2_SHAKE_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_49_11_3_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_49_11_3_SSK", BCObjectIdentifiers.snova_49_11_3_ssk, new SnovaKeyFactorySpi.SNOVA_49_11_3_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_49_11_3_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_49_11_3_ESK", BCObjectIdentifiers.snova_49_11_3_esk, new SnovaKeyFactorySpi.SNOVA_49_11_3_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_49_11_3_SHAKE_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_49_11_3_SHAKE_SSK", BCObjectIdentifiers.snova_49_11_3_shake_ssk, new SnovaKeyFactorySpi.SNOVA_49_11_3_SHAKE_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_49_11_3_SHAKE_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_49_11_3_SHAKE_ESK", BCObjectIdentifiers.snova_49_11_3_shake_esk, new SnovaKeyFactorySpi.SNOVA_49_11_3_SHAKE_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_56_25_2_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_56_25_2_SSK", BCObjectIdentifiers.snova_56_25_2_ssk, new SnovaKeyFactorySpi.SNOVA_56_25_2_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_56_25_2_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_56_25_2_ESK", BCObjectIdentifiers.snova_56_25_2_esk, new SnovaKeyFactorySpi.SNOVA_56_25_2_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_56_25_2_SHAKE_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_56_25_2_SHAKE_SSK", BCObjectIdentifiers.snova_56_25_2_shake_ssk, new SnovaKeyFactorySpi.SNOVA_56_25_2_SHAKE_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_56_25_2_SHAKE_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_56_25_2_SHAKE_ESK", BCObjectIdentifiers.snova_56_25_2_shake_esk, new SnovaKeyFactorySpi.SNOVA_56_25_2_SHAKE_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_60_10_4_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_60_10_4_SSK", BCObjectIdentifiers.snova_60_10_4_ssk, new SnovaKeyFactorySpi.SNOVA_60_10_4_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_60_10_4_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_60_10_4_ESK", BCObjectIdentifiers.snova_60_10_4_esk, new SnovaKeyFactorySpi.SNOVA_60_10_4_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_60_10_4_SHAKE_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_60_10_4_SHAKE_SSK", BCObjectIdentifiers.snova_60_10_4_shake_ssk, new SnovaKeyFactorySpi.SNOVA_60_10_4_SHAKE_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_60_10_4_SHAKE_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_60_10_4_SHAKE_ESK", BCObjectIdentifiers.snova_60_10_4_shake_esk, new SnovaKeyFactorySpi.SNOVA_60_10_4_SHAKE_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_66_15_3_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_66_15_3_SSK", BCObjectIdentifiers.snova_66_15_3_ssk, new SnovaKeyFactorySpi.SNOVA_66_15_3_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_66_15_3_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_66_15_3_ESK", BCObjectIdentifiers.snova_66_15_3_esk, new SnovaKeyFactorySpi.SNOVA_66_15_3_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_66_15_3_SHAKE_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_66_15_3_SHAKE_SSK", BCObjectIdentifiers.snova_66_15_3_shake_ssk, new SnovaKeyFactorySpi.SNOVA_66_15_3_SHAKE_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_66_15_3_SHAKE_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_66_15_3_SHAKE_ESK", BCObjectIdentifiers.snova_66_15_3_shake_esk, new SnovaKeyFactorySpi.SNOVA_66_15_3_SHAKE_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_75_33_2_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_75_33_2_SSK", BCObjectIdentifiers.snova_75_33_2_ssk, new SnovaKeyFactorySpi.SNOVA_75_33_2_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_75_33_2_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_75_33_2_ESK", BCObjectIdentifiers.snova_75_33_2_esk, new SnovaKeyFactorySpi.SNOVA_75_33_2_ESK());
            addKeyFactoryAlgorithm(provider, "SNOVA_75_33_2_SHAKE_SSK", PREFIX + "SnovaKeyFactorySpi$SNOVA_75_33_2_SHAKE_SSK", BCObjectIdentifiers.snova_75_33_2_shake_ssk, new SnovaKeyFactorySpi.SNOVA_75_33_2_SHAKE_SSK());
            addKeyFactoryAlgorithm(provider, "SNOVA_75_33_2_SHAKE_ESK", PREFIX + "SnovaKeyFactorySpi$SNOVA_75_33_2_SHAKE_ESK", BCObjectIdentifiers.snova_75_33_2_shake_esk, new SnovaKeyFactorySpi.SNOVA_75_33_2_SHAKE_ESK());

            
            provider.addAlgorithm("KeyPairGenerator.Snova", PREFIX + "SnovaKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "SNOVA_24_5_4_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_24_5_4_SSK", BCObjectIdentifiers.snova_24_5_4_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_24_5_4_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_24_5_4_ESK", BCObjectIdentifiers.snova_24_5_4_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_24_5_4_SHAKE_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_24_5_4_SHAKE_SSK", BCObjectIdentifiers.snova_24_5_4_shake_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_24_5_4_SHAKE_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_24_5_4_SHAKE_ESK", BCObjectIdentifiers.snova_24_5_4_shake_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_24_5_5_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_24_5_5_SSK", BCObjectIdentifiers.snova_24_5_5_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_24_5_5_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_24_5_5_ESK", BCObjectIdentifiers.snova_24_5_5_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_24_5_5_SHAKE_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_24_5_5_SHAKE_SSK", BCObjectIdentifiers.snova_24_5_5_shake_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_24_5_5_SHAKE_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_24_5_5_SHAKE_ESK", BCObjectIdentifiers.snova_24_5_5_shake_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_25_8_3_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_25_8_3_SSK", BCObjectIdentifiers.snova_25_8_3_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_25_8_3_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_25_8_3_ESK", BCObjectIdentifiers.snova_25_8_3_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_25_8_3_SHAKE_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_25_8_3_SHAKE_SSK", BCObjectIdentifiers.snova_25_8_3_shake_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_25_8_3_SHAKE_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_25_8_3_SHAKE_ESK", BCObjectIdentifiers.snova_25_8_3_shake_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_29_6_5_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_29_6_5_SSK", BCObjectIdentifiers.snova_29_6_5_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_29_6_5_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_29_6_5_ESK", BCObjectIdentifiers.snova_29_6_5_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_29_6_5_SHAKE_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_29_6_5_SHAKE_SSK", BCObjectIdentifiers.snova_29_6_5_shake_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_29_6_5_SHAKE_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_29_6_5_SHAKE_ESK", BCObjectIdentifiers.snova_29_6_5_shake_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_37_8_4_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_37_8_4_SSK", BCObjectIdentifiers.snova_37_8_4_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_37_8_4_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_37_8_4_ESK", BCObjectIdentifiers.snova_37_8_4_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_37_8_4_SHAKE_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_37_8_4_SHAKE_SSK", BCObjectIdentifiers.snova_37_8_4_shake_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_37_8_4_SHAKE_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_37_8_4_SHAKE_ESK", BCObjectIdentifiers.snova_37_8_4_shake_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_37_17_2_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_37_17_2_SSK", BCObjectIdentifiers.snova_37_17_2_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_37_17_2_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_37_17_2_ESK", BCObjectIdentifiers.snova_37_17_2_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_37_17_2_SHAKE_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_37_17_2_SHAKE_SSK", BCObjectIdentifiers.snova_37_17_2_shake_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_37_17_2_SHAKE_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_37_17_2_SHAKE_ESK", BCObjectIdentifiers.snova_37_17_2_shake_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_49_11_3_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_49_11_3_SSK", BCObjectIdentifiers.snova_49_11_3_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_49_11_3_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_49_11_3_ESK", BCObjectIdentifiers.snova_49_11_3_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_49_11_3_SHAKE_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_49_11_3_SHAKE_SSK", BCObjectIdentifiers.snova_49_11_3_shake_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_49_11_3_SHAKE_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_49_11_3_SHAKE_ESK", BCObjectIdentifiers.snova_49_11_3_shake_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_56_25_2_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_56_25_2_SSK", BCObjectIdentifiers.snova_56_25_2_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_56_25_2_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_56_25_2_ESK", BCObjectIdentifiers.snova_56_25_2_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_56_25_2_SHAKE_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_56_25_2_SHAKE_SSK", BCObjectIdentifiers.snova_56_25_2_shake_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_56_25_2_SHAKE_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_56_25_2_SHAKE_ESK", BCObjectIdentifiers.snova_56_25_2_shake_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_60_10_4_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_60_10_4_SSK", BCObjectIdentifiers.snova_60_10_4_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_60_10_4_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_60_10_4_ESK", BCObjectIdentifiers.snova_60_10_4_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_60_10_4_SHAKE_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_60_10_4_SHAKE_SSK", BCObjectIdentifiers.snova_60_10_4_shake_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_60_10_4_SHAKE_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_60_10_4_SHAKE_ESK", BCObjectIdentifiers.snova_60_10_4_shake_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_66_15_3_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_66_15_3_SSK", BCObjectIdentifiers.snova_66_15_3_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_66_15_3_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_66_15_3_ESK", BCObjectIdentifiers.snova_66_15_3_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_66_15_3_SHAKE_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_66_15_3_SHAKE_SSK", BCObjectIdentifiers.snova_66_15_3_shake_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_66_15_3_SHAKE_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_66_15_3_SHAKE_ESK", BCObjectIdentifiers.snova_66_15_3_shake_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_75_33_2_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_75_33_2_SSK", BCObjectIdentifiers.snova_75_33_2_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_75_33_2_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_75_33_2_ESK", BCObjectIdentifiers.snova_75_33_2_esk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_75_33_2_SHAKE_SSK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_75_33_2_SHAKE_SSK", BCObjectIdentifiers.snova_75_33_2_shake_ssk);
            addKeyPairGeneratorAlgorithm(provider, "SNOVA_75_33_2_SHAKE_ESK", PREFIX + "SnovaKeyPairGeneratorSpi$SNOVA_75_33_2_SHAKE_ESK", BCObjectIdentifiers.snova_75_33_2_shake_esk);
            
            addSignatureAlgorithm(provider, "Snova", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.snova);

            addSignatureAlgorithm(provider, "SNOVA_24_5_4_SSK", PREFIX + "SignatureSpi$SNOVA_24_5_4_SSK", BCObjectIdentifiers.snova_24_5_4_ssk);
            addSignatureAlgorithm(provider, "SNOVA_24_5_4_ESK", PREFIX + "SignatureSpi$SNOVA_24_5_4_ESK", BCObjectIdentifiers.snova_24_5_4_esk);
            addSignatureAlgorithm(provider, "SNOVA_24_5_4_SHAKE_SSK", PREFIX + "SignatureSpi$SNOVA_24_5_4_SHAKE_SSK", BCObjectIdentifiers.snova_24_5_4_shake_ssk);
            addSignatureAlgorithm(provider, "SNOVA_24_5_4_SHAKE_ESK", PREFIX + "SignatureSpi$SNOVA_24_5_4_SHAKE_ESK", BCObjectIdentifiers.snova_24_5_4_shake_esk);
            addSignatureAlgorithm(provider, "SNOVA_24_5_5_SSK", PREFIX + "SignatureSpi$SNOVA_24_5_5_SSK", BCObjectIdentifiers.snova_24_5_5_ssk);
            addSignatureAlgorithm(provider, "SNOVA_24_5_5_ESK", PREFIX + "SignatureSpi$SNOVA_24_5_5_ESK", BCObjectIdentifiers.snova_24_5_5_esk);
            addSignatureAlgorithm(provider, "SNOVA_24_5_5_SHAKE_SSK", PREFIX + "SignatureSpi$SNOVA_24_5_5_SHAKE_SSK", BCObjectIdentifiers.snova_24_5_5_shake_ssk);
            addSignatureAlgorithm(provider, "SNOVA_24_5_5_SHAKE_ESK", PREFIX + "SignatureSpi$SNOVA_24_5_5_SHAKE_ESK", BCObjectIdentifiers.snova_24_5_5_shake_esk);
            addSignatureAlgorithm(provider, "SNOVA_25_8_3_SSK", PREFIX + "SignatureSpi$SNOVA_25_8_3_SSK", BCObjectIdentifiers.snova_25_8_3_ssk);
            addSignatureAlgorithm(provider, "SNOVA_25_8_3_ESK", PREFIX + "SignatureSpi$SNOVA_25_8_3_ESK", BCObjectIdentifiers.snova_25_8_3_esk);
            addSignatureAlgorithm(provider, "SNOVA_25_8_3_SHAKE_SSK", PREFIX + "SignatureSpi$SNOVA_25_8_3_SHAKE_SSK", BCObjectIdentifiers.snova_25_8_3_shake_ssk);
            addSignatureAlgorithm(provider, "SNOVA_25_8_3_SHAKE_ESK", PREFIX + "SignatureSpi$SNOVA_25_8_3_SHAKE_ESK", BCObjectIdentifiers.snova_25_8_3_shake_esk);
            addSignatureAlgorithm(provider, "SNOVA_29_6_5_SSK", PREFIX + "SignatureSpi$SNOVA_29_6_5_SSK", BCObjectIdentifiers.snova_29_6_5_ssk);
            addSignatureAlgorithm(provider, "SNOVA_29_6_5_ESK", PREFIX + "SignatureSpi$SNOVA_29_6_5_ESK", BCObjectIdentifiers.snova_29_6_5_esk);
            addSignatureAlgorithm(provider, "SNOVA_29_6_5_SHAKE_SSK", PREFIX + "SignatureSpi$SNOVA_29_6_5_SHAKE_SSK", BCObjectIdentifiers.snova_29_6_5_shake_ssk);
            addSignatureAlgorithm(provider, "SNOVA_29_6_5_SHAKE_ESK", PREFIX + "SignatureSpi$SNOVA_29_6_5_SHAKE_ESK", BCObjectIdentifiers.snova_29_6_5_shake_esk);
            addSignatureAlgorithm(provider, "SNOVA_37_8_4_SSK", PREFIX + "SignatureSpi$SNOVA_37_8_4_SSK", BCObjectIdentifiers.snova_37_8_4_ssk);
            addSignatureAlgorithm(provider, "SNOVA_37_8_4_ESK", PREFIX + "SignatureSpi$SNOVA_37_8_4_ESK", BCObjectIdentifiers.snova_37_8_4_esk);
            addSignatureAlgorithm(provider, "SNOVA_37_8_4_SHAKE_SSK", PREFIX + "SignatureSpi$SNOVA_37_8_4_SHAKE_SSK", BCObjectIdentifiers.snova_37_8_4_shake_ssk);
            addSignatureAlgorithm(provider, "SNOVA_37_8_4_SHAKE_ESK", PREFIX + "SignatureSpi$SNOVA_37_8_4_SHAKE_ESK", BCObjectIdentifiers.snova_37_8_4_shake_esk);
            addSignatureAlgorithm(provider, "SNOVA_37_17_2_SSK", PREFIX + "SignatureSpi$SNOVA_37_17_2_SSK", BCObjectIdentifiers.snova_37_17_2_ssk);
            addSignatureAlgorithm(provider, "SNOVA_37_17_2_ESK", PREFIX + "SignatureSpi$SNOVA_37_17_2_ESK", BCObjectIdentifiers.snova_37_17_2_esk);
            addSignatureAlgorithm(provider, "SNOVA_37_17_2_SHAKE_SSK", PREFIX + "SignatureSpi$SNOVA_37_17_2_SHAKE_SSK", BCObjectIdentifiers.snova_37_17_2_shake_ssk);
            addSignatureAlgorithm(provider, "SNOVA_37_17_2_SHAKE_ESK", PREFIX + "SignatureSpi$SNOVA_37_17_2_SHAKE_ESK", BCObjectIdentifiers.snova_37_17_2_shake_esk);
            addSignatureAlgorithm(provider, "SNOVA_49_11_3_SSK", PREFIX + "SignatureSpi$SNOVA_49_11_3_SSK", BCObjectIdentifiers.snova_49_11_3_ssk);
            addSignatureAlgorithm(provider, "SNOVA_49_11_3_ESK", PREFIX + "SignatureSpi$SNOVA_49_11_3_ESK", BCObjectIdentifiers.snova_49_11_3_esk);
            addSignatureAlgorithm(provider, "SNOVA_49_11_3_SHAKE_SSK", PREFIX + "SignatureSpi$SNOVA_49_11_3_SHAKE_SSK", BCObjectIdentifiers.snova_49_11_3_shake_ssk);
            addSignatureAlgorithm(provider, "SNOVA_49_11_3_SHAKE_ESK", PREFIX + "SignatureSpi$SNOVA_49_11_3_SHAKE_ESK", BCObjectIdentifiers.snova_49_11_3_shake_esk);
            addSignatureAlgorithm(provider, "SNOVA_56_25_2_SSK", PREFIX + "SignatureSpi$SNOVA_56_25_2_SSK", BCObjectIdentifiers.snova_56_25_2_ssk);
            addSignatureAlgorithm(provider, "SNOVA_56_25_2_ESK", PREFIX + "SignatureSpi$SNOVA_56_25_2_ESK", BCObjectIdentifiers.snova_56_25_2_esk);
            addSignatureAlgorithm(provider, "SNOVA_56_25_2_SHAKE_SSK", PREFIX + "SignatureSpi$SNOVA_56_25_2_SHAKE_SSK", BCObjectIdentifiers.snova_56_25_2_shake_ssk);
            addSignatureAlgorithm(provider, "SNOVA_56_25_2_SHAKE_ESK", PREFIX + "SignatureSpi$SNOVA_56_25_2_SHAKE_ESK", BCObjectIdentifiers.snova_56_25_2_shake_esk);
            addSignatureAlgorithm(provider, "SNOVA_60_10_4_SSK", PREFIX + "SignatureSpi$SNOVA_60_10_4_SSK", BCObjectIdentifiers.snova_60_10_4_ssk);
            addSignatureAlgorithm(provider, "SNOVA_60_10_4_ESK", PREFIX + "SignatureSpi$SNOVA_60_10_4_ESK", BCObjectIdentifiers.snova_60_10_4_esk);
            addSignatureAlgorithm(provider, "SNOVA_60_10_4_SHAKE_SSK", PREFIX + "SignatureSpi$SNOVA_60_10_4_SHAKE_SSK", BCObjectIdentifiers.snova_60_10_4_shake_ssk);
            addSignatureAlgorithm(provider, "SNOVA_60_10_4_SHAKE_ESK", PREFIX + "SignatureSpi$SNOVA_60_10_4_SHAKE_ESK", BCObjectIdentifiers.snova_60_10_4_shake_esk);
            addSignatureAlgorithm(provider, "SNOVA_66_15_3_SSK", PREFIX + "SignatureSpi$SNOVA_66_15_3_SSK", BCObjectIdentifiers.snova_66_15_3_ssk);
            addSignatureAlgorithm(provider, "SNOVA_66_15_3_ESK", PREFIX + "SignatureSpi$SNOVA_66_15_3_ESK", BCObjectIdentifiers.snova_66_15_3_esk);
            addSignatureAlgorithm(provider, "SNOVA_66_15_3_SHAKE_SSK", PREFIX + "SignatureSpi$SNOVA_66_15_3_SHAKE_SSK", BCObjectIdentifiers.snova_66_15_3_shake_ssk);
            addSignatureAlgorithm(provider, "SNOVA_66_15_3_SHAKE_ESK", PREFIX + "SignatureSpi$SNOVA_66_15_3_SHAKE_ESK", BCObjectIdentifiers.snova_66_15_3_shake_esk);
            addSignatureAlgorithm(provider, "SNOVA_75_33_2_SSK", PREFIX + "SignatureSpi$SNOVA_75_33_2_SSK", BCObjectIdentifiers.snova_75_33_2_ssk);
            addSignatureAlgorithm(provider, "SNOVA_75_33_2_ESK", PREFIX + "SignatureSpi$SNOVA_75_33_2_ESK", BCObjectIdentifiers.snova_75_33_2_esk);
            addSignatureAlgorithm(provider, "SNOVA_75_33_2_SHAKE_SSK", PREFIX + "SignatureSpi$SNOVA_75_33_2_SHAKE_SSK", BCObjectIdentifiers.snova_75_33_2_shake_ssk);
            addSignatureAlgorithm(provider, "SNOVA_75_33_2_SHAKE_ESK", PREFIX + "SignatureSpi$SNOVA_75_33_2_SHAKE_ESK", BCObjectIdentifiers.snova_75_33_2_shake_esk);
        }
    }
}
