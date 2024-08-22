package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
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

            addKeyFactoryAlgorithm(provider, "ML-KEM-512", PREFIX + "KyberKeyFactorySpi$Kyber512", NISTObjectIdentifiers.id_alg_ml_kem_512, new KyberKeyFactorySpi.Kyber512());
            addKeyFactoryAlgorithm(provider, "ML-KEM-768", PREFIX + "KyberKeyFactorySpi$Kyber768", NISTObjectIdentifiers.id_alg_ml_kem_768, new KyberKeyFactorySpi.Kyber768());
            addKeyFactoryAlgorithm(provider, "ML-KEM-1024", PREFIX + "KyberKeyFactorySpi$Kyber1024", NISTObjectIdentifiers.id_alg_ml_kem_1024, new KyberKeyFactorySpi.Kyber1024());
            provider.addAlgorithm("Alg.Alias.KeyFactory.KYBER512", "ML-KEM-512");
            provider.addAlgorithm("Alg.Alias.KeyFactory.KYBER768", "ML-KEM-768");
            provider.addAlgorithm("Alg.Alias.KeyFactory.KYBER1024", "ML-KEM-1024");

            provider.addAlgorithm("KeyPairGenerator.ML-KEM", PREFIX + "KyberKeyPairGeneratorSpi");
            provider.addAlgorithm("KeyPairGenerator.ML-KEM-512", PREFIX + "KyberKeyPairGeneratorSpi$Kyber512");
            provider.addAlgorithm("KeyPairGenerator.ML-KEM-768", PREFIX + "KyberKeyPairGeneratorSpi$Kyber768");
            provider.addAlgorithm("KeyPairGenerator.ML-KEM-1024", PREFIX + "KyberKeyPairGeneratorSpi$Kyber1024");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.KYBER", "ML-KEM");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.KYBER512", "ML-KEM-512");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.KYBER768", "ML-KEM-768");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.KYBER1024", "ML-KEM-1024");

            provider.addAlgorithm("KeyGenerator.KYBER", PREFIX + "KyberKeyGeneratorSpi");

            addKeyGeneratorAlgorithm(provider, "ML-KEM-512", PREFIX + "KyberKeyGeneratorSpi$Kyber512", NISTObjectIdentifiers.id_alg_ml_kem_512);
            addKeyGeneratorAlgorithm(provider, "ML-KEM-768", PREFIX + "KyberKeyGeneratorSpi$Kyber768", NISTObjectIdentifiers.id_alg_ml_kem_768);
            addKeyGeneratorAlgorithm(provider, "ML-KEM-1024", PREFIX + "KyberKeyGeneratorSpi$Kyber1024", NISTObjectIdentifiers.id_alg_ml_kem_1024);
            provider.addAlgorithm("Alg.Alias.KeyGenerator.KYBER512", "ML-KEM-512");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.KYBER768", "ML-KEM-768");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.KYBER1024", "ML-KEM-1024");

            AsymmetricKeyInfoConverter keyFact = new KyberKeyFactorySpi();

            provider.addAlgorithm("Cipher.KYBER", PREFIX + "KyberCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_kyber, "KYBER");

            addCipherAlgorithm(provider, "ML-KEM-512", PREFIX + "KyberCipherSpi$Kyber512", NISTObjectIdentifiers.id_alg_ml_kem_512);
            addCipherAlgorithm(provider, "ML-KEM-768", PREFIX + "KyberCipherSpi$Kyber768", NISTObjectIdentifiers.id_alg_ml_kem_768);
            addCipherAlgorithm(provider, "ML-KEM-1024", PREFIX + "KyberCipherSpi$Kyber1024", NISTObjectIdentifiers.id_alg_ml_kem_1024);
            provider.addAlgorithm("Alg.Alias.Cipher.KYBER512", "ML-KEM-512");
            provider.addAlgorithm("Alg.Alias.Cipher.KYBER768", "ML-KEM-768");
            provider.addAlgorithm("Alg.Alias.Cipher.KYBER1024", "ML-KEM-1024");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_kyber, "KYBER", keyFact);
        }
    }
}
