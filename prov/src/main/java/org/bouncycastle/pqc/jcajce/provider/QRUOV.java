package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.qruov.QRUOVKeyFactorySpi;

public class QRUOV
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.qruov.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.QRUOV", PREFIX + "QRUOVKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "QRUOV1Q127L3V156M54", PREFIX + "QRUOVKeyFactorySpi$QRUOV1Q127L3V156M54", BCObjectIdentifiers.qruov1q127L3v156m54, new QRUOVKeyFactorySpi.QRUOV1Q127L3V156M54());
            addKeyFactoryAlgorithm(provider, "QRUOV1Q31L3V165M60", PREFIX + "QRUOVKeyFactorySpi$QRUOV1Q31L3V165M60", BCObjectIdentifiers.qruov1q31L3v165m60, new QRUOVKeyFactorySpi.QRUOV1Q31L3V165M60());
            addKeyFactoryAlgorithm(provider, "QRUOV1Q31L10V600M70", PREFIX + "QRUOVKeyFactorySpi$QRUOV1Q31L10V600M70", BCObjectIdentifiers.qruov1q31L10v600m70, new QRUOVKeyFactorySpi.QRUOV1Q31L10V600M70());
            addKeyFactoryAlgorithm(provider, "QRUOV1Q7L10V740M100", PREFIX + "QRUOVKeyFactorySpi$QRUOV1Q7L10V740M100", BCObjectIdentifiers.qruov1q7L10v740m100, new QRUOVKeyFactorySpi.QRUOV1Q7L10V740M100());
            addKeyFactoryAlgorithm(provider, "QRUOV3Q127L3V228M78", PREFIX + "QRUOVKeyFactorySpi$QRUOV3Q127L3V228M78", BCObjectIdentifiers.qruov3q127L3v228m78, new QRUOVKeyFactorySpi.QRUOV3Q127L3V228M78());
            addKeyFactoryAlgorithm(provider, "QRUOV3Q31L3V246M87", PREFIX + "QRUOVKeyFactorySpi$QRUOV3Q31L3V246M87", BCObjectIdentifiers.qruov3q31L3v246m87, new QRUOVKeyFactorySpi.QRUOV3Q31L3V246M87());
            addKeyFactoryAlgorithm(provider, "QRUOV3Q31L10V890M100", PREFIX + "QRUOVKeyFactorySpi$QRUOV3Q31L10V890M100", BCObjectIdentifiers.qruov3q31L10v890m100, new QRUOVKeyFactorySpi.QRUOV3Q31L10V890M100());
            addKeyFactoryAlgorithm(provider, "QRUOV3Q7L10V1100M140", PREFIX + "QRUOVKeyFactorySpi$QRUOV3Q7L10V1100M140", BCObjectIdentifiers.qruov3q7L10v1100m140, new QRUOVKeyFactorySpi.QRUOV3Q7L10V1100M140());
            addKeyFactoryAlgorithm(provider, "QRUOV5Q127L3V306M105", PREFIX + "QRUOVKeyFactorySpi$QRUOV5Q127L3V306M105", BCObjectIdentifiers.qruov5q127L3v306m105, new QRUOVKeyFactorySpi.QRUOV5Q127L3V306M105());
            addKeyFactoryAlgorithm(provider, "QRUOV5Q31L3V324M114", PREFIX + "QRUOVKeyFactorySpi$QRUOV5Q31L3V324M114", BCObjectIdentifiers.qruov5q31L3v324m114, new QRUOVKeyFactorySpi.QRUOV5Q31L3V324M114());
            addKeyFactoryAlgorithm(provider, "QRUOV5Q31L10V1120M120", PREFIX + "QRUOVKeyFactorySpi$QRUOV5Q31L10V1120M120", BCObjectIdentifiers.qruov5q31L10v1120m120, new QRUOVKeyFactorySpi.QRUOV5Q31L10V1120M120());
            addKeyFactoryAlgorithm(provider, "QRUOV5Q7L10V1490M190", PREFIX + "QRUOVKeyFactorySpi$QRUOV5Q7L10V1490M190", BCObjectIdentifiers.qruov5q7L10v1490m190, new QRUOVKeyFactorySpi.QRUOV5Q7L10V1490M190());

            provider.addAlgorithm("KeyPairGenerator.QRUOV", PREFIX + "QRUOVKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "QRUOV1Q127L3V156M54", PREFIX + "QRUOVKeyPairGeneratorSpi$QRUOV1Q127L3V156M54", BCObjectIdentifiers.qruov1q127L3v156m54);
            addKeyPairGeneratorAlgorithm(provider, "QRUOV1Q31L3V165M60", PREFIX + "QRUOVKeyPairGeneratorSpi$QRUOV1Q31L3V165M60", BCObjectIdentifiers.qruov1q31L3v165m60);
            addKeyPairGeneratorAlgorithm(provider, "QRUOV1Q31L10V600M70", PREFIX + "QRUOVKeyPairGeneratorSpi$QRUOV1Q31L10V600M70", BCObjectIdentifiers.qruov1q31L10v600m70);
            addKeyPairGeneratorAlgorithm(provider, "QRUOV1Q7L10V740M100", PREFIX + "QRUOVKeyPairGeneratorSpi$QRUOV1Q7L10V740M100", BCObjectIdentifiers.qruov1q7L10v740m100);
            addKeyPairGeneratorAlgorithm(provider, "QRUOV3Q127L3V228M78", PREFIX + "QRUOVKeyPairGeneratorSpi$QRUOV3Q127L3V228M78", BCObjectIdentifiers.qruov3q127L3v228m78);
            addKeyPairGeneratorAlgorithm(provider, "QRUOV3Q31L3V246M87", PREFIX + "QRUOVKeyPairGeneratorSpi$QRUOV3Q31L3V246M87", BCObjectIdentifiers.qruov3q31L3v246m87);
            addKeyPairGeneratorAlgorithm(provider, "QRUOV3Q31L10V890M100", PREFIX + "QRUOVKeyPairGeneratorSpi$QRUOV3Q31L10V890M100", BCObjectIdentifiers.qruov3q31L10v890m100);
            addKeyPairGeneratorAlgorithm(provider, "QRUOV3Q7L10V1100M140", PREFIX + "QRUOVKeyPairGeneratorSpi$QRUOV3Q7L10V1100M140", BCObjectIdentifiers.qruov3q7L10v1100m140);
            addKeyPairGeneratorAlgorithm(provider, "QRUOV5Q127L3V306M105", PREFIX + "QRUOVKeyPairGeneratorSpi$QRUOV5Q127L3V306M105", BCObjectIdentifiers.qruov5q127L3v306m105);
            addKeyPairGeneratorAlgorithm(provider, "QRUOV5Q31L3V324M114", PREFIX + "QRUOVKeyPairGeneratorSpi$QRUOV5Q31L3V324M114", BCObjectIdentifiers.qruov5q31L3v324m114);
            addKeyPairGeneratorAlgorithm(provider, "QRUOV5Q31L10V1120M120", PREFIX + "QRUOVKeyPairGeneratorSpi$QRUOV5Q31L10V1120M120", BCObjectIdentifiers.qruov5q31L10v1120m120);
            addKeyPairGeneratorAlgorithm(provider, "QRUOV5Q7L10V1490M190", PREFIX + "QRUOVKeyPairGeneratorSpi$QRUOV5Q7L10V1490M190", BCObjectIdentifiers.qruov5q7L10v1490m190);

            addSignatureAlgorithm(provider, "QRUOV", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.qruov);

            addSignatureAlgorithm(provider, "QRUOV1Q127L3V156M54", PREFIX + "SignatureSpi$QRUOV1Q127L3V156M54", BCObjectIdentifiers.qruov1q127L3v156m54);
            addSignatureAlgorithm(provider, "QRUOV1Q31L3V165M60", PREFIX + "SignatureSpi$QRUOV1Q31L3V165M60", BCObjectIdentifiers.qruov1q31L3v165m60);
            addSignatureAlgorithm(provider, "QRUOV1Q31L10V600M70", PREFIX + "SignatureSpi$QRUOV1Q31L10V600M70", BCObjectIdentifiers.qruov1q31L10v600m70);
            addSignatureAlgorithm(provider, "QRUOV1Q7L10V740M100", PREFIX + "SignatureSpi$QRUOV1Q7L10V740M100", BCObjectIdentifiers.qruov1q7L10v740m100);
            addSignatureAlgorithm(provider, "QRUOV3Q127L3V228M78", PREFIX + "SignatureSpi$QRUOV3Q127L3V228M78", BCObjectIdentifiers.qruov3q127L3v228m78);
            addSignatureAlgorithm(provider, "QRUOV3Q31L3V246M87", PREFIX + "SignatureSpi$QRUOV3Q31L3V246M87", BCObjectIdentifiers.qruov3q31L3v246m87);
            addSignatureAlgorithm(provider, "QRUOV3Q31L10V890M100", PREFIX + "SignatureSpi$QRUOV3Q31L10V890M100", BCObjectIdentifiers.qruov3q31L10v890m100);
            addSignatureAlgorithm(provider, "QRUOV3Q7L10V1100M140", PREFIX + "SignatureSpi$QRUOV3Q7L10V1100M140", BCObjectIdentifiers.qruov3q7L10v1100m140);
            addSignatureAlgorithm(provider, "QRUOV5Q127L3V306M105", PREFIX + "SignatureSpi$QRUOV5Q127L3V306M105", BCObjectIdentifiers.qruov5q127L3v306m105);
            addSignatureAlgorithm(provider, "QRUOV5Q31L3V324M114", PREFIX + "SignatureSpi$QRUOV5Q31L3V324M114", BCObjectIdentifiers.qruov5q31L3v324m114);
            addSignatureAlgorithm(provider, "QRUOV5Q31L10V1120M120", PREFIX + "SignatureSpi$QRUOV5Q31L10V1120M120", BCObjectIdentifiers.qruov5q31L10v1120m120);
            addSignatureAlgorithm(provider, "QRUOV5Q7L10V1490M190", PREFIX + "SignatureSpi$QRUOV5Q7L10V1490M190", BCObjectIdentifiers.qruov5q7L10v1490m190);
        }
    }
}
