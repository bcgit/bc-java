package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.MLKEMKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class MLKEM
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".mlkem.";

    public static class Mappings
            extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.ML-KEM", PREFIX + "MLKEMKeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.MLKEM", "ML-KEM");

            addKeyFactoryAlgorithm(provider, "ML-KEM-512", PREFIX + "MLKEMKeyFactorySpi$MLKEM512", NISTObjectIdentifiers.id_alg_ml_kem_512, new MLKEMKeyFactorySpi.MLKEM512());
            addKeyFactoryAlgorithm(provider, "ML-KEM-768", PREFIX + "MLKEMKeyFactorySpi$MLKEM768", NISTObjectIdentifiers.id_alg_ml_kem_768, new MLKEMKeyFactorySpi.MLKEM768());
            addKeyFactoryAlgorithm(provider, "ML-KEM-1024", PREFIX + "MLKEMKeyFactorySpi$MLKEM1024", NISTObjectIdentifiers.id_alg_ml_kem_1024, new MLKEMKeyFactorySpi.MLKEM1024());

            provider.addAlgorithm("KeyPairGenerator.ML-KEM", PREFIX + "MLKEMKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.MLKEM", "ML-KEM");

            addKeyPairGeneratorAlgorithm(provider, "ML-KEM-512", PREFIX + "MLKEMKeyPairGeneratorSpi$MLKEM512", NISTObjectIdentifiers.id_alg_ml_kem_512);
            addKeyPairGeneratorAlgorithm(provider, "ML-KEM-768", PREFIX + "MLKEMKeyPairGeneratorSpi$MLKEM768", NISTObjectIdentifiers.id_alg_ml_kem_768);
            addKeyPairGeneratorAlgorithm(provider, "ML-KEM-1024", PREFIX + "MLKEMKeyPairGeneratorSpi$MLKEM1024", NISTObjectIdentifiers.id_alg_ml_kem_1024);

            provider.addAlgorithm("KeyGenerator.ML-KEM", PREFIX + "MLKEMKeyGeneratorSpi");

            addKeyGeneratorAlgorithm(provider, "ML-KEM-512", PREFIX + "MLKEMKeyGeneratorSpi$MLKEM512", NISTObjectIdentifiers.id_alg_ml_kem_512);
            addKeyGeneratorAlgorithm(provider, "ML-KEM-768", PREFIX + "MLKEMKeyGeneratorSpi$MLKEM768", NISTObjectIdentifiers.id_alg_ml_kem_768);
            addKeyGeneratorAlgorithm(provider, "ML-KEM-1024", PREFIX + "MLKEMKeyGeneratorSpi$MLKEM1024", NISTObjectIdentifiers.id_alg_ml_kem_1024);

            AsymmetricKeyInfoConverter keyFact = new MLKEMKeyFactorySpi();

            provider.addAlgorithm("Cipher.ML-KEM", PREFIX + "MLKEMCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher.MLKEM", "ML-KEM");

            addCipherAlgorithm(provider, "ML-KEM-512", PREFIX + "MLKEMCipherSpi$MLKEM512", NISTObjectIdentifiers.id_alg_ml_kem_512);
            addCipherAlgorithm(provider, "ML-KEM-768", PREFIX + "MLKEMCipherSpi$MLKEM768", NISTObjectIdentifiers.id_alg_ml_kem_768);
            addCipherAlgorithm(provider, "ML-KEM-1024", PREFIX + "MLKEMCipherSpi$MLKEM1024", NISTObjectIdentifiers.id_alg_ml_kem_1024);

            provider.addKeyInfoConverter(NISTObjectIdentifiers.id_alg_ml_kem_512, keyFact);
            provider.addKeyInfoConverter(NISTObjectIdentifiers.id_alg_ml_kem_768, keyFact);
            provider.addKeyInfoConverter(NISTObjectIdentifiers.id_alg_ml_kem_1024, keyFact);

            provider.addAlgorithm("KEM.ML-KEM", PREFIX + "MLKEMSpi");
            provider.addAlgorithm("Alg.Alias.KEM." + NISTObjectIdentifiers.id_alg_ml_kem_512, "ML-KEM");
            provider.addAlgorithm("Alg.Alias.KEM." + NISTObjectIdentifiers.id_alg_ml_kem_768, "ML-KEM");
            provider.addAlgorithm("Alg.Alias.KEM." + NISTObjectIdentifiers.id_alg_ml_kem_1024, "ML-KEM");
        }
    }
}
