package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.kyber.KyberKeyFactorySpi;

public class Kyber
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".kyber.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.KYBER", PREFIX + "KyberKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "KYBER512", PREFIX + "KyberKeyFactorySpi$Kyber512", BCObjectIdentifiers.kyber512, new KyberKeyFactorySpi.Kyber512());
            addKeyFactoryAlgorithm(provider, "KYBER768", PREFIX + "KyberKeyFactorySpi$Kyber768", BCObjectIdentifiers.kyber768, new KyberKeyFactorySpi.Kyber768());
            addKeyFactoryAlgorithm(provider, "KYBER1024", PREFIX + "KyberKeyFactorySpi$Kyber1024", BCObjectIdentifiers.kyber1024, new KyberKeyFactorySpi.Kyber1024());
            addKeyFactoryAlgorithm(provider, "KYBER512-AES", PREFIX + "KyberKeyFactorySpi$Kyber512_AES", BCObjectIdentifiers.kyber512_aes, new KyberKeyFactorySpi.Kyber512_AES());
            addKeyFactoryAlgorithm(provider, "KYBER768-AES", PREFIX + "KyberKeyFactorySpi$Kyber768_AES", BCObjectIdentifiers.kyber768_aes, new KyberKeyFactorySpi.Kyber768_AES());
            addKeyFactoryAlgorithm(provider, "KYBER1024-AES", PREFIX + "KyberKeyFactorySpi$Kyber1024_AES", BCObjectIdentifiers.kyber1024_aes, new KyberKeyFactorySpi.Kyber1024_AES());

            provider.addAlgorithm("KeyPairGenerator.KYBER", PREFIX + "KyberKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "KYBER512", PREFIX + "KyberKeyPairGeneratorSpi$Kyber512", BCObjectIdentifiers.kyber512);
            addKeyPairGeneratorAlgorithm(provider, "KYBER768", PREFIX + "KyberKeyPairGeneratorSpi$Kyber768", BCObjectIdentifiers.kyber768);
            addKeyPairGeneratorAlgorithm(provider, "KYBER1024", PREFIX + "KyberKeyPairGeneratorSpi$Kyber1024", BCObjectIdentifiers.kyber1024);
            addKeyPairGeneratorAlgorithm(provider, "KYBER512-AES", PREFIX + "KyberKeyPairGeneratorSpi$Kyber512_AES", BCObjectIdentifiers.kyber512_aes);
            addKeyPairGeneratorAlgorithm(provider, "KYBER768-AES", PREFIX + "KyberKeyPairGeneratorSpi$Kyber768_AES", BCObjectIdentifiers.kyber768_aes);
            addKeyPairGeneratorAlgorithm(provider, "KYBER1024-AES", PREFIX + "KyberKeyPairGeneratorSpi$Kyber1024_AES", BCObjectIdentifiers.kyber1024_aes);

            provider.addAlgorithm("KeyGenerator.KYBER", PREFIX + "KyberKeyGeneratorSpi");

            addKeyGeneratorAlgorithm(provider, "KYBER512", PREFIX + "KyberKeyGeneratorSpi$Kyber512", BCObjectIdentifiers.kyber512);
            addKeyGeneratorAlgorithm(provider, "KYBER768", PREFIX + "KyberKeyGeneratorSpi$Kyber768", BCObjectIdentifiers.kyber768);
            addKeyGeneratorAlgorithm(provider, "KYBER1024", PREFIX + "KyberKeyGeneratorSpi$Kyber1024", BCObjectIdentifiers.kyber1024);
            addKeyGeneratorAlgorithm(provider, "KYBER512-AES", PREFIX + "KyberKeyGeneratorSpi$Kyber512_AES", BCObjectIdentifiers.kyber512_aes);
            addKeyGeneratorAlgorithm(provider, "KYBER768-AES", PREFIX + "KyberKeyGeneratorSpi$Kyber768_AES", BCObjectIdentifiers.kyber768_aes);
            addKeyGeneratorAlgorithm(provider, "KYBER1024-AES", PREFIX + "KyberKeyGeneratorSpi$Kyber1024_AES", BCObjectIdentifiers.kyber1024_aes);

            AsymmetricKeyInfoConverter keyFact = new KyberKeyFactorySpi();

            provider.addAlgorithm("Cipher.KYBER", PREFIX + "KyberCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_kyber, "KYBER");

            addCipherAlgorithm(provider, "KYBER512", PREFIX + "KyberCipherSpi$Kyber512", BCObjectIdentifiers.kyber512);
            addCipherAlgorithm(provider, "KYBER768", PREFIX + "KyberCipherSpi$Kyber768", BCObjectIdentifiers.kyber768);
            addCipherAlgorithm(provider, "KYBER1024", PREFIX + "KyberCipherSpi$Kyber1024", BCObjectIdentifiers.kyber1024);
            addCipherAlgorithm(provider, "KYBER512-AES", PREFIX + "KyberCipherSpi$Kyber512_AES", BCObjectIdentifiers.kyber512_aes);
            addCipherAlgorithm(provider, "KYBER768-AES", PREFIX + "KyberCipherSpi$Kyber768_AES", BCObjectIdentifiers.kyber768_aes);
            addCipherAlgorithm(provider, "KYBER1024-AES", PREFIX + "KyberCipherSpi$Kyber1024_AES", BCObjectIdentifiers.kyber1024_aes);

            registerOid(provider, BCObjectIdentifiers.pqc_kem_kyber, "KYBER", keyFact);
        }
    }
}
