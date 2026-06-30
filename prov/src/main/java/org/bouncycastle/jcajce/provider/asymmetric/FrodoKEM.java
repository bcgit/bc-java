package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.internal.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.frodokem.FrodoKEMKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class FrodoKEM
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".frodokem.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.FRODOKEM", PREFIX + "FrodoKEMKeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.FrodoKEM", "FRODOKEM");

            addKeyFactoryAlgorithm(provider, "frodokem976shake", PREFIX + "FrodoKEMKeyFactorySpi$Frodokem976Shake", ISOIECObjectIdentifiers.frodokem976_shake, new FrodoKEMKeyFactorySpi.Frodokem976Shake());
            addKeyFactoryAlgorithm(provider, "frodokem1344shake", PREFIX + "FrodoKEMKeyFactorySpi$Frodokem1344Shake", ISOIECObjectIdentifiers.frodokem1344_shake, new FrodoKEMKeyFactorySpi.Frodokem1344Shake());
            addKeyFactoryAlgorithm(provider, "efrodokem976shake", PREFIX + "FrodoKEMKeyFactorySpi$EFrodokem976Shake", ISOIECObjectIdentifiers.efrodokem976_shake, new FrodoKEMKeyFactorySpi.EFrodokem976Shake());
            addKeyFactoryAlgorithm(provider, "efrodokem1344shake", PREFIX + "FrodoKEMKeyFactorySpi$EFrodokem1344Shake", ISOIECObjectIdentifiers.efrodokem1344_shake, new FrodoKEMKeyFactorySpi.EFrodokem1344Shake());
            addKeyFactoryAlgorithm(provider, "frodokem976aes", PREFIX + "FrodoKEMKeyFactorySpi$Frodokem976Aes", ISOIECObjectIdentifiers.frodokem976_aes, new FrodoKEMKeyFactorySpi.Frodokem976Aes());
            addKeyFactoryAlgorithm(provider, "frodokem1344aes", PREFIX + "FrodoKEMKeyFactorySpi$Frodokem1344Aes", ISOIECObjectIdentifiers.frodokem1344_aes, new FrodoKEMKeyFactorySpi.Frodokem1344Aes());
            addKeyFactoryAlgorithm(provider, "efrodokem976aes", PREFIX + "FrodoKEMKeyFactorySpi$EFrodokem976Aes", ISOIECObjectIdentifiers.efrodokem976_aes, new FrodoKEMKeyFactorySpi.EFrodokem976Aes());
            addKeyFactoryAlgorithm(provider, "efrodokem1344aes", PREFIX + "FrodoKEMKeyFactorySpi$EFrodokem1344Aes", ISOIECObjectIdentifiers.efrodokem1344_aes, new FrodoKEMKeyFactorySpi.EFrodokem1344Aes());

            provider.addAlgorithm("KeyPairGenerator.FRODOKEM", PREFIX + "FrodoKEMKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.FrodoKEM", "FRODOKEM");

            addKeyPairGeneratorAlgorithm(provider, "frodokem976shake", PREFIX + "FrodoKEMKeyPairGeneratorSpi$Frodokem976Shake", ISOIECObjectIdentifiers.frodokem976_shake);
            addKeyPairGeneratorAlgorithm(provider, "frodokem1344shake", PREFIX + "FrodoKEMKeyPairGeneratorSpi$Frodokem1344Shake", ISOIECObjectIdentifiers.frodokem1344_shake);
            addKeyPairGeneratorAlgorithm(provider, "efrodokem976shake", PREFIX + "FrodoKEMKeyPairGeneratorSpi$EFrodokem976Shake", ISOIECObjectIdentifiers.efrodokem976_shake);
            addKeyPairGeneratorAlgorithm(provider, "efrodokem1344shake", PREFIX + "FrodoKEMKeyPairGeneratorSpi$EFrodokem1344Shake", ISOIECObjectIdentifiers.efrodokem1344_shake);
            addKeyPairGeneratorAlgorithm(provider, "frodokem976aes", PREFIX + "FrodoKEMKeyPairGeneratorSpi$Frodokem976Aes", ISOIECObjectIdentifiers.frodokem976_aes);
            addKeyPairGeneratorAlgorithm(provider, "frodokem1344aes", PREFIX + "FrodoKEMKeyPairGeneratorSpi$Frodokem1344Aes", ISOIECObjectIdentifiers.frodokem1344_aes);
            addKeyPairGeneratorAlgorithm(provider, "efrodokem976aes", PREFIX + "FrodoKEMKeyPairGeneratorSpi$EFrodokem976Aes", ISOIECObjectIdentifiers.efrodokem976_aes);
            addKeyPairGeneratorAlgorithm(provider, "efrodokem1344aes", PREFIX + "FrodoKEMKeyPairGeneratorSpi$EFrodokem1344Aes", ISOIECObjectIdentifiers.efrodokem1344_aes);

            provider.addAlgorithm("KeyGenerator.FRODOKEM", PREFIX + "FrodoKEMKeyGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.FrodoKEM", "FRODOKEM");

            addKeyGeneratorAlgorithm(provider, "frodokem976shake", PREFIX + "FrodoKEMKeyGeneratorSpi$Frodokem976Shake", ISOIECObjectIdentifiers.frodokem976_shake);
            addKeyGeneratorAlgorithm(provider, "frodokem1344shake", PREFIX + "FrodoKEMKeyGeneratorSpi$Frodokem1344Shake", ISOIECObjectIdentifiers.frodokem1344_shake);
            addKeyGeneratorAlgorithm(provider, "efrodokem976shake", PREFIX + "FrodoKEMKeyGeneratorSpi$EFrodokem976Shake", ISOIECObjectIdentifiers.efrodokem976_shake);
            addKeyGeneratorAlgorithm(provider, "efrodokem1344shake", PREFIX + "FrodoKEMKeyGeneratorSpi$EFrodokem1344Shake", ISOIECObjectIdentifiers.efrodokem1344_shake);
            addKeyGeneratorAlgorithm(provider, "frodokem976aes", PREFIX + "FrodoKEMKeyGeneratorSpi$Frodokem976Aes", ISOIECObjectIdentifiers.frodokem976_aes);
            addKeyGeneratorAlgorithm(provider, "frodokem1344aes", PREFIX + "FrodoKEMKeyGeneratorSpi$Frodokem1344Aes", ISOIECObjectIdentifiers.frodokem1344_aes);
            addKeyGeneratorAlgorithm(provider, "efrodokem976aes", PREFIX + "FrodoKEMKeyGeneratorSpi$EFrodokem976Aes", ISOIECObjectIdentifiers.efrodokem976_aes);
            addKeyGeneratorAlgorithm(provider, "efrodokem1344aes", PREFIX + "FrodoKEMKeyGeneratorSpi$EFrodokem1344Aes", ISOIECObjectIdentifiers.efrodokem1344_aes);

            AsymmetricKeyInfoConverter keyFact = new FrodoKEMKeyFactorySpi();

            provider.addAlgorithm("Cipher.FRODOKEM", PREFIX + "FrodoKEMCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher.FrodoKEM", "FRODOKEM");

            addCipherAlgorithm(provider, "frodokem976shake", PREFIX + "FrodoKEMCipherSpi$Frodokem976Shake", ISOIECObjectIdentifiers.frodokem976_shake);
            addCipherAlgorithm(provider, "frodokem1344shake", PREFIX + "FrodoKEMCipherSpi$Frodokem1344Shake", ISOIECObjectIdentifiers.frodokem1344_shake);
            addCipherAlgorithm(provider, "efrodokem976shake", PREFIX + "FrodoKEMCipherSpi$EFrodokem976Shake", ISOIECObjectIdentifiers.efrodokem976_shake);
            addCipherAlgorithm(provider, "efrodokem1344shake", PREFIX + "FrodoKEMCipherSpi$EFrodokem1344Shake", ISOIECObjectIdentifiers.efrodokem1344_shake);
            addCipherAlgorithm(provider, "frodokem976aes", PREFIX + "FrodoKEMCipherSpi$Frodokem976Aes", ISOIECObjectIdentifiers.frodokem976_aes);
            addCipherAlgorithm(provider, "frodokem1344aes", PREFIX + "FrodoKEMCipherSpi$Frodokem1344Aes", ISOIECObjectIdentifiers.frodokem1344_aes);
            addCipherAlgorithm(provider, "efrodokem976aes", PREFIX + "FrodoKEMCipherSpi$EFrodokem976Aes", ISOIECObjectIdentifiers.efrodokem976_aes);
            addCipherAlgorithm(provider, "efrodokem1344aes", PREFIX + "FrodoKEMCipherSpi$EFrodokem1344Aes", ISOIECObjectIdentifiers.efrodokem1344_aes);

            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.frodokem976_shake, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.frodokem1344_shake, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.efrodokem976_shake, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.efrodokem1344_shake, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.frodokem976_aes, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.frodokem1344_aes, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.efrodokem976_aes, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.efrodokem1344_aes, keyFact);
        }
    }
}
