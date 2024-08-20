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

            addKeyFactoryAlgorithm(provider, "KYBER512", PREFIX + "KyberKeyFactorySpi$Kyber512", NISTObjectIdentifiers.id_alg_ml_kem_512, new KyberKeyFactorySpi.Kyber512());
            addKeyFactoryAlgorithm(provider, "KYBER768", PREFIX + "KyberKeyFactorySpi$Kyber768", NISTObjectIdentifiers.id_alg_ml_kem_768, new KyberKeyFactorySpi.Kyber768());
            addKeyFactoryAlgorithm(provider, "KYBER1024", PREFIX + "KyberKeyFactorySpi$Kyber1024", NISTObjectIdentifiers.id_alg_ml_kem_1024, new KyberKeyFactorySpi.Kyber1024());

            provider.addAlgorithm("KeyPairGenerator.KYBER", PREFIX + "KyberKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "KYBER512", PREFIX + "KyberKeyPairGeneratorSpi$Kyber512", NISTObjectIdentifiers.id_alg_ml_kem_512);
            addKeyPairGeneratorAlgorithm(provider, "KYBER768", PREFIX + "KyberKeyPairGeneratorSpi$Kyber768", NISTObjectIdentifiers.id_alg_ml_kem_768);
            addKeyPairGeneratorAlgorithm(provider, "KYBER1024", PREFIX + "KyberKeyPairGeneratorSpi$Kyber1024", NISTObjectIdentifiers.id_alg_ml_kem_1024);

            provider.addAlgorithm("KeyGenerator.KYBER", PREFIX + "KyberKeyGeneratorSpi");

            addKeyGeneratorAlgorithm(provider, "KYBER512", PREFIX + "KyberKeyGeneratorSpi$Kyber512", NISTObjectIdentifiers.id_alg_ml_kem_512);
            addKeyGeneratorAlgorithm(provider, "KYBER768", PREFIX + "KyberKeyGeneratorSpi$Kyber768", NISTObjectIdentifiers.id_alg_ml_kem_768);
            addKeyGeneratorAlgorithm(provider, "KYBER1024", PREFIX + "KyberKeyGeneratorSpi$Kyber1024", NISTObjectIdentifiers.id_alg_ml_kem_1024);

            AsymmetricKeyInfoConverter keyFact = new KyberKeyFactorySpi();

            provider.addAlgorithm("Cipher.KYBER", PREFIX + "KyberCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_kyber, "KYBER");

            addCipherAlgorithm(provider, "KYBER512", PREFIX + "KyberCipherSpi$Kyber512", NISTObjectIdentifiers.id_alg_ml_kem_512);
            addCipherAlgorithm(provider, "KYBER768", PREFIX + "KyberCipherSpi$Kyber768", NISTObjectIdentifiers.id_alg_ml_kem_768);
            addCipherAlgorithm(provider, "KYBER1024", PREFIX + "KyberCipherSpi$Kyber1024", NISTObjectIdentifiers.id_alg_ml_kem_1024);
           
            registerOid(provider, BCObjectIdentifiers.pqc_kem_kyber, "KYBER", keyFact);
        }
    }
}
