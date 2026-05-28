package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.sdith.SDitHKeyFactorySpi;

public class SDitH
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.sdith.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.SDitH", PREFIX + "SDitHKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SDitH", PREFIX + "SDitHKeyPairGeneratorSpi");
            addSignatureAlgorithm(provider, "SDitH", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.sdith);

            // Per-variant parameter-locked SPIs.
            addKeyFactoryAlgorithm(provider, "SDITH-HYPERCUBE-CAT1-GF256",
                PREFIX + "SDitHKeyFactorySpi$HypercubeCat1Gf256",
                BCObjectIdentifiers.sdith_hypercube_cat1_gf256,
                new SDitHKeyFactorySpi.HypercubeCat1Gf256());
            addKeyFactoryAlgorithm(provider, "SDITH-HYPERCUBE-CAT3-GF256",
                PREFIX + "SDitHKeyFactorySpi$HypercubeCat3Gf256",
                BCObjectIdentifiers.sdith_hypercube_cat3_gf256,
                new SDitHKeyFactorySpi.HypercubeCat3Gf256());
            addKeyFactoryAlgorithm(provider, "SDITH-HYPERCUBE-CAT5-GF256",
                PREFIX + "SDitHKeyFactorySpi$HypercubeCat5Gf256",
                BCObjectIdentifiers.sdith_hypercube_cat5_gf256,
                new SDitHKeyFactorySpi.HypercubeCat5Gf256());
            addKeyFactoryAlgorithm(provider, "SDITH-HYPERCUBE-CAT1-P251",
                PREFIX + "SDitHKeyFactorySpi$HypercubeCat1P251",
                BCObjectIdentifiers.sdith_hypercube_cat1_p251,
                new SDitHKeyFactorySpi.HypercubeCat1P251());
            addKeyFactoryAlgorithm(provider, "SDITH-HYPERCUBE-CAT3-P251",
                PREFIX + "SDitHKeyFactorySpi$HypercubeCat3P251",
                BCObjectIdentifiers.sdith_hypercube_cat3_p251,
                new SDitHKeyFactorySpi.HypercubeCat3P251());
            addKeyFactoryAlgorithm(provider, "SDITH-HYPERCUBE-CAT5-P251",
                PREFIX + "SDitHKeyFactorySpi$HypercubeCat5P251",
                BCObjectIdentifiers.sdith_hypercube_cat5_p251,
                new SDitHKeyFactorySpi.HypercubeCat5P251());

            addKeyPairGeneratorAlgorithm(provider, "SDITH-HYPERCUBE-CAT1-GF256",
                PREFIX + "SDitHKeyPairGeneratorSpi$HypercubeCat1Gf256",
                BCObjectIdentifiers.sdith_hypercube_cat1_gf256);
            addKeyPairGeneratorAlgorithm(provider, "SDITH-HYPERCUBE-CAT3-GF256",
                PREFIX + "SDitHKeyPairGeneratorSpi$HypercubeCat3Gf256",
                BCObjectIdentifiers.sdith_hypercube_cat3_gf256);
            addKeyPairGeneratorAlgorithm(provider, "SDITH-HYPERCUBE-CAT5-GF256",
                PREFIX + "SDitHKeyPairGeneratorSpi$HypercubeCat5Gf256",
                BCObjectIdentifiers.sdith_hypercube_cat5_gf256);
            addKeyPairGeneratorAlgorithm(provider, "SDITH-HYPERCUBE-CAT1-P251",
                PREFIX + "SDitHKeyPairGeneratorSpi$HypercubeCat1P251",
                BCObjectIdentifiers.sdith_hypercube_cat1_p251);
            addKeyPairGeneratorAlgorithm(provider, "SDITH-HYPERCUBE-CAT3-P251",
                PREFIX + "SDitHKeyPairGeneratorSpi$HypercubeCat3P251",
                BCObjectIdentifiers.sdith_hypercube_cat3_p251);
            addKeyPairGeneratorAlgorithm(provider, "SDITH-HYPERCUBE-CAT5-P251",
                PREFIX + "SDitHKeyPairGeneratorSpi$HypercubeCat5P251",
                BCObjectIdentifiers.sdith_hypercube_cat5_p251);

            addSignatureAlgorithm(provider, "SDITH-HYPERCUBE-CAT1-GF256",
                PREFIX + "SignatureSpi$HypercubeCat1Gf256",
                BCObjectIdentifiers.sdith_hypercube_cat1_gf256);
            addSignatureAlgorithm(provider, "SDITH-HYPERCUBE-CAT3-GF256",
                PREFIX + "SignatureSpi$HypercubeCat3Gf256",
                BCObjectIdentifiers.sdith_hypercube_cat3_gf256);
            addSignatureAlgorithm(provider, "SDITH-HYPERCUBE-CAT5-GF256",
                PREFIX + "SignatureSpi$HypercubeCat5Gf256",
                BCObjectIdentifiers.sdith_hypercube_cat5_gf256);
            addSignatureAlgorithm(provider, "SDITH-HYPERCUBE-CAT1-P251",
                PREFIX + "SignatureSpi$HypercubeCat1P251",
                BCObjectIdentifiers.sdith_hypercube_cat1_p251);
            addSignatureAlgorithm(provider, "SDITH-HYPERCUBE-CAT3-P251",
                PREFIX + "SignatureSpi$HypercubeCat3P251",
                BCObjectIdentifiers.sdith_hypercube_cat3_p251);
            addSignatureAlgorithm(provider, "SDITH-HYPERCUBE-CAT5-P251",
                PREFIX + "SignatureSpi$HypercubeCat5P251",
                BCObjectIdentifiers.sdith_hypercube_cat5_p251);

            addKeyFactoryAlgorithm(provider, "SDITH-THRESHOLD-CAT1-GF256",
                PREFIX + "SDitHKeyFactorySpi$ThresholdCat1Gf256",
                BCObjectIdentifiers.sdith_threshold_cat1_gf256,
                new SDitHKeyFactorySpi.ThresholdCat1Gf256());
            addKeyFactoryAlgorithm(provider, "SDITH-THRESHOLD-CAT3-GF256",
                PREFIX + "SDitHKeyFactorySpi$ThresholdCat3Gf256",
                BCObjectIdentifiers.sdith_threshold_cat3_gf256,
                new SDitHKeyFactorySpi.ThresholdCat3Gf256());
            addKeyFactoryAlgorithm(provider, "SDITH-THRESHOLD-CAT5-GF256",
                PREFIX + "SDitHKeyFactorySpi$ThresholdCat5Gf256",
                BCObjectIdentifiers.sdith_threshold_cat5_gf256,
                new SDitHKeyFactorySpi.ThresholdCat5Gf256());
            addKeyFactoryAlgorithm(provider, "SDITH-THRESHOLD-CAT1-P251",
                PREFIX + "SDitHKeyFactorySpi$ThresholdCat1P251",
                BCObjectIdentifiers.sdith_threshold_cat1_p251,
                new SDitHKeyFactorySpi.ThresholdCat1P251());
            addKeyFactoryAlgorithm(provider, "SDITH-THRESHOLD-CAT3-P251",
                PREFIX + "SDitHKeyFactorySpi$ThresholdCat3P251",
                BCObjectIdentifiers.sdith_threshold_cat3_p251,
                new SDitHKeyFactorySpi.ThresholdCat3P251());
            addKeyFactoryAlgorithm(provider, "SDITH-THRESHOLD-CAT5-P251",
                PREFIX + "SDitHKeyFactorySpi$ThresholdCat5P251",
                BCObjectIdentifiers.sdith_threshold_cat5_p251,
                new SDitHKeyFactorySpi.ThresholdCat5P251());

            addKeyPairGeneratorAlgorithm(provider, "SDITH-THRESHOLD-CAT1-GF256",
                PREFIX + "SDitHKeyPairGeneratorSpi$ThresholdCat1Gf256",
                BCObjectIdentifiers.sdith_threshold_cat1_gf256);
            addKeyPairGeneratorAlgorithm(provider, "SDITH-THRESHOLD-CAT3-GF256",
                PREFIX + "SDitHKeyPairGeneratorSpi$ThresholdCat3Gf256",
                BCObjectIdentifiers.sdith_threshold_cat3_gf256);
            addKeyPairGeneratorAlgorithm(provider, "SDITH-THRESHOLD-CAT5-GF256",
                PREFIX + "SDitHKeyPairGeneratorSpi$ThresholdCat5Gf256",
                BCObjectIdentifiers.sdith_threshold_cat5_gf256);
            addKeyPairGeneratorAlgorithm(provider, "SDITH-THRESHOLD-CAT1-P251",
                PREFIX + "SDitHKeyPairGeneratorSpi$ThresholdCat1P251",
                BCObjectIdentifiers.sdith_threshold_cat1_p251);
            addKeyPairGeneratorAlgorithm(provider, "SDITH-THRESHOLD-CAT3-P251",
                PREFIX + "SDitHKeyPairGeneratorSpi$ThresholdCat3P251",
                BCObjectIdentifiers.sdith_threshold_cat3_p251);
            addKeyPairGeneratorAlgorithm(provider, "SDITH-THRESHOLD-CAT5-P251",
                PREFIX + "SDitHKeyPairGeneratorSpi$ThresholdCat5P251",
                BCObjectIdentifiers.sdith_threshold_cat5_p251);

            addSignatureAlgorithm(provider, "SDITH-THRESHOLD-CAT1-GF256",
                PREFIX + "SignatureSpi$ThresholdCat1Gf256",
                BCObjectIdentifiers.sdith_threshold_cat1_gf256);
            addSignatureAlgorithm(provider, "SDITH-THRESHOLD-CAT3-GF256",
                PREFIX + "SignatureSpi$ThresholdCat3Gf256",
                BCObjectIdentifiers.sdith_threshold_cat3_gf256);
            addSignatureAlgorithm(provider, "SDITH-THRESHOLD-CAT5-GF256",
                PREFIX + "SignatureSpi$ThresholdCat5Gf256",
                BCObjectIdentifiers.sdith_threshold_cat5_gf256);
            addSignatureAlgorithm(provider, "SDITH-THRESHOLD-CAT1-P251",
                PREFIX + "SignatureSpi$ThresholdCat1P251",
                BCObjectIdentifiers.sdith_threshold_cat1_p251);
            addSignatureAlgorithm(provider, "SDITH-THRESHOLD-CAT3-P251",
                PREFIX + "SignatureSpi$ThresholdCat3P251",
                BCObjectIdentifiers.sdith_threshold_cat3_p251);
            addSignatureAlgorithm(provider, "SDITH-THRESHOLD-CAT5-P251",
                PREFIX + "SignatureSpi$ThresholdCat5P251",
                BCObjectIdentifiers.sdith_threshold_cat5_p251);
        }
    }
}
