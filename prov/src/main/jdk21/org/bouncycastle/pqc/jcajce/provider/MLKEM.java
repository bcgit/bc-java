package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.MLKEMKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class MLKEM
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".mlkem.";

    public static class Mappings
            extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.ML-KEM", PREFIX + "MLKEMKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.ML-KEM", PREFIX + "MLKEMKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.ML-KEM", PREFIX + "MLKEMKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new MLKEMKeyFactorySpi();

            provider.addAlgorithm("Cipher.ML-KEM", PREFIX + "MLKEMCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher", "ML-KEM");

            registerOid(provider, NISTObjectIdentifiers.id_alg_ml_kem_512, "ML-KEM", keyFact);
            registerOid(provider, NISTObjectIdentifiers.id_alg_ml_kem_768, "ML-KEM", keyFact);
            registerOid(provider, NISTObjectIdentifiers.id_alg_ml_kem_1024, "ML-KEM", keyFact);

            provider.addAlgorithm("Kem.ML-KEM", PREFIX + "MLKEMSpi");
            provider.addAlgorithm("Alg.Alias.Kem", "ML-KEM");
        }
    }
}
