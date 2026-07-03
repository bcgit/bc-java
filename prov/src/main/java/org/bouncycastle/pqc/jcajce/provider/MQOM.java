package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.mqom.MQOMKeyFactorySpi;
import org.bouncycastle.util.Exceptions;

public class MQOM
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.mqom.";

    private static final String[][] VARIANTS = {
        {"MQOM2-CAT1-GF2-FAST-R3",    "mqom2_cat1_gf2_fast_r3",    "C1Gf2Fr3"},
        {"MQOM2-CAT1-GF2-FAST-R5",    "mqom2_cat1_gf2_fast_r5",    "C1Gf2Fr5"},
        {"MQOM2-CAT1-GF2-SHORT-R3",   "mqom2_cat1_gf2_short_r3",   "C1Gf2Sr3"},
        {"MQOM2-CAT1-GF2-SHORT-R5",   "mqom2_cat1_gf2_short_r5",   "C1Gf2Sr5"},
        {"MQOM2-CAT1-GF16-FAST-R3",   "mqom2_cat1_gf16_fast_r3",   "C1Gf16Fr3"},
        {"MQOM2-CAT1-GF16-FAST-R5",   "mqom2_cat1_gf16_fast_r5",   "C1Gf16Fr5"},
        {"MQOM2-CAT1-GF16-SHORT-R3",  "mqom2_cat1_gf16_short_r3",  "C1Gf16Sr3"},
        {"MQOM2-CAT1-GF16-SHORT-R5",  "mqom2_cat1_gf16_short_r5",  "C1Gf16Sr5"},
        {"MQOM2-CAT1-GF256-FAST-R3",  "mqom2_cat1_gf256_fast_r3",  "C1Gf256Fr3"},
        {"MQOM2-CAT1-GF256-FAST-R5",  "mqom2_cat1_gf256_fast_r5",  "C1Gf256Fr5"},
        {"MQOM2-CAT1-GF256-SHORT-R3", "mqom2_cat1_gf256_short_r3", "C1Gf256Sr3"},
        {"MQOM2-CAT1-GF256-SHORT-R5", "mqom2_cat1_gf256_short_r5", "C1Gf256Sr5"},
        {"MQOM2-CAT3-GF2-FAST-R3",    "mqom2_cat3_gf2_fast_r3",    "C3Gf2Fr3"},
        {"MQOM2-CAT3-GF2-FAST-R5",    "mqom2_cat3_gf2_fast_r5",    "C3Gf2Fr5"},
        {"MQOM2-CAT3-GF2-SHORT-R3",   "mqom2_cat3_gf2_short_r3",   "C3Gf2Sr3"},
        {"MQOM2-CAT3-GF2-SHORT-R5",   "mqom2_cat3_gf2_short_r5",   "C3Gf2Sr5"},
        {"MQOM2-CAT3-GF16-FAST-R3",   "mqom2_cat3_gf16_fast_r3",   "C3Gf16Fr3"},
        {"MQOM2-CAT3-GF16-FAST-R5",   "mqom2_cat3_gf16_fast_r5",   "C3Gf16Fr5"},
        {"MQOM2-CAT3-GF16-SHORT-R3",  "mqom2_cat3_gf16_short_r3",  "C3Gf16Sr3"},
        {"MQOM2-CAT3-GF16-SHORT-R5",  "mqom2_cat3_gf16_short_r5",  "C3Gf16Sr5"},
        {"MQOM2-CAT3-GF256-FAST-R3",  "mqom2_cat3_gf256_fast_r3",  "C3Gf256Fr3"},
        {"MQOM2-CAT3-GF256-FAST-R5",  "mqom2_cat3_gf256_fast_r5",  "C3Gf256Fr5"},
        {"MQOM2-CAT3-GF256-SHORT-R3", "mqom2_cat3_gf256_short_r3", "C3Gf256Sr3"},
        {"MQOM2-CAT3-GF256-SHORT-R5", "mqom2_cat3_gf256_short_r5", "C3Gf256Sr5"},
        {"MQOM2-CAT5-GF2-FAST-R3",    "mqom2_cat5_gf2_fast_r3",    "C5Gf2Fr3"},
        {"MQOM2-CAT5-GF2-FAST-R5",    "mqom2_cat5_gf2_fast_r5",    "C5Gf2Fr5"},
        {"MQOM2-CAT5-GF2-SHORT-R3",   "mqom2_cat5_gf2_short_r3",   "C5Gf2Sr3"},
        {"MQOM2-CAT5-GF2-SHORT-R5",   "mqom2_cat5_gf2_short_r5",   "C5Gf2Sr5"},
        {"MQOM2-CAT5-GF16-FAST-R3",   "mqom2_cat5_gf16_fast_r3",   "C5Gf16Fr3"},
        {"MQOM2-CAT5-GF16-FAST-R5",   "mqom2_cat5_gf16_fast_r5",   "C5Gf16Fr5"},
        {"MQOM2-CAT5-GF16-SHORT-R3",  "mqom2_cat5_gf16_short_r3",  "C5Gf16Sr3"},
        {"MQOM2-CAT5-GF16-SHORT-R5",  "mqom2_cat5_gf16_short_r5",  "C5Gf16Sr5"},
        {"MQOM2-CAT5-GF256-FAST-R3",  "mqom2_cat5_gf256_fast_r3",  "C5Gf256Fr3"},
        {"MQOM2-CAT5-GF256-FAST-R5",  "mqom2_cat5_gf256_fast_r5",  "C5Gf256Fr5"},
        {"MQOM2-CAT5-GF256-SHORT-R3", "mqom2_cat5_gf256_short_r3", "C5Gf256Sr3"},
        {"MQOM2-CAT5-GF256-SHORT-R5", "mqom2_cat5_gf256_short_r5", "C5Gf256Sr5"},
    };

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.MQOM", PREFIX + "MQOMKeyFactorySpi$Base");
            provider.addAlgorithm("KeyPairGenerator.MQOM", PREFIX + "MQOMKeyPairGeneratorSpi$Base");
            provider.addAlgorithm("Signature.MQOM", PREFIX + "SignatureSpi$Base");

            for (int i = 0; i < VARIANTS.length; i++)
            {
                String alias = VARIANTS[i][0];
                String oidName = VARIANTS[i][1];
                String suffix = VARIANTS[i][2];

                ASN1ObjectIdentifier oid;
                try
                {
                    oid = (ASN1ObjectIdentifier)BCObjectIdentifiers.class.getField(oidName).get(null);
                }
                catch (Exception e)
                {
                    throw Exceptions.illegalStateException("missing BC OID for MQOM variant " + alias, e);
                }

                addKeyFactoryAlgorithm(provider, alias, PREFIX + "MQOMKeyFactorySpi$" + suffix, oid, new MQOMKeyFactorySpi(oid));
                addKeyPairGeneratorAlgorithm(provider, alias, PREFIX + "MQOMKeyPairGeneratorSpi$" + suffix, oid);
                addSignatureAlgorithm(provider, alias, PREFIX + "SignatureSpi$" + suffix, oid);
            }
        }
    }
}
