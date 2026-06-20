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

            provider.addAlgorithm("KeyPairGenerator.FRODOKEM", PREFIX + "FrodoKEMKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.FrodoKEM", "FRODOKEM");

            addKeyPairGeneratorAlgorithm(provider, "frodokem976shake", PREFIX + "FrodoKEMKeyPairGeneratorSpi$Frodokem976Shake", ISOIECObjectIdentifiers.frodokem976_shake);
            addKeyPairGeneratorAlgorithm(provider, "frodokem1344shake", PREFIX + "FrodoKEMKeyPairGeneratorSpi$Frodokem1344Shake", ISOIECObjectIdentifiers.frodokem1344_shake);
            addKeyPairGeneratorAlgorithm(provider, "efrodokem976shake", PREFIX + "FrodoKEMKeyPairGeneratorSpi$EFrodokem976Shake", ISOIECObjectIdentifiers.efrodokem976_shake);
            addKeyPairGeneratorAlgorithm(provider, "efrodokem1344shake", PREFIX + "FrodoKEMKeyPairGeneratorSpi$EFrodokem1344Shake", ISOIECObjectIdentifiers.efrodokem1344_shake);

            provider.addAlgorithm("KeyGenerator.FRODOKEM", PREFIX + "FrodoKEMKeyGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.FrodoKEM", "FRODOKEM");

            addKeyGeneratorAlgorithm(provider, "frodokem976shake", PREFIX + "FrodoKEMKeyGeneratorSpi$Frodokem976Shake", ISOIECObjectIdentifiers.frodokem976_shake);
            addKeyGeneratorAlgorithm(provider, "frodokem1344shake", PREFIX + "FrodoKEMKeyGeneratorSpi$Frodokem1344Shake", ISOIECObjectIdentifiers.frodokem1344_shake);
            addKeyGeneratorAlgorithm(provider, "efrodokem976shake", PREFIX + "FrodoKEMKeyGeneratorSpi$EFrodokem976Shake", ISOIECObjectIdentifiers.efrodokem976_shake);
            addKeyGeneratorAlgorithm(provider, "efrodokem1344shake", PREFIX + "FrodoKEMKeyGeneratorSpi$EFrodokem1344Shake", ISOIECObjectIdentifiers.efrodokem1344_shake);

            AsymmetricKeyInfoConverter keyFact = new FrodoKEMKeyFactorySpi();

            provider.addAlgorithm("Cipher.FRODOKEM", PREFIX + "FrodoKEMCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher.FrodoKEM", "FRODOKEM");

            addCipherAlgorithm(provider, "frodokem976shake", PREFIX + "FrodoKEMCipherSpi$Frodokem976Shake", ISOIECObjectIdentifiers.frodokem976_shake);
            addCipherAlgorithm(provider, "frodokem1344shake", PREFIX + "FrodoKEMCipherSpi$Frodokem1344Shake", ISOIECObjectIdentifiers.frodokem1344_shake);
            addCipherAlgorithm(provider, "efrodokem976shake", PREFIX + "FrodoKEMCipherSpi$EFrodokem976Shake", ISOIECObjectIdentifiers.efrodokem976_shake);
            addCipherAlgorithm(provider, "efrodokem1344shake", PREFIX + "FrodoKEMCipherSpi$EFrodokem1344Shake", ISOIECObjectIdentifiers.efrodokem1344_shake);

            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.frodokem976_shake, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.frodokem1344_shake, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.efrodokem976_shake, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.efrodokem1344_shake, keyFact);
        }
    }
}
