package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.dilithium.DilithiumKeyFactorySpi;

public class Dilithium
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".dilithium.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.DILITHIUM", PREFIX + "DilithiumKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.DILITHIUM", PREFIX + "DilithiumKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "DILITHIUM2", PREFIX + "DilithiumKeyPairGeneratorSpi$Base2", BCObjectIdentifiers.dilithium2);
            addKeyPairGeneratorAlgorithm(provider, "DILITHIUM3", PREFIX + "DilithiumKeyPairGeneratorSpi$Base3", BCObjectIdentifiers.dilithium3);
            addKeyPairGeneratorAlgorithm(provider, "DILITHIUM5", PREFIX + "DilithiumKeyPairGeneratorSpi$Base5", BCObjectIdentifiers.dilithium5);
            addKeyPairGeneratorAlgorithm(provider, "DILITHIUM2-AES", PREFIX + "DilithiumKeyPairGeneratorSpi$Base2_AES", BCObjectIdentifiers.dilithium2_aes);
            addKeyPairGeneratorAlgorithm(provider, "DILITHIUM3-AES", PREFIX + "DilithiumKeyPairGeneratorSpi$Base3_AES", BCObjectIdentifiers.dilithium3_aes);
            addKeyPairGeneratorAlgorithm(provider, "DILITHIUM5-AES", PREFIX + "DilithiumKeyPairGeneratorSpi$Base5_AES", BCObjectIdentifiers.dilithium5_aes);

            addSignatureAlgorithm(provider, "DILITHIUM", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.dilithium);

            addSignatureAlgorithm(provider, "DILITHIUM2", PREFIX + "SignatureSpi$Base2", BCObjectIdentifiers.dilithium2);
            addSignatureAlgorithm(provider, "DILITHIUM3", PREFIX + "SignatureSpi$Base3", BCObjectIdentifiers.dilithium3);
            addSignatureAlgorithm(provider, "DILITHIUM5", PREFIX + "SignatureSpi$Base5", BCObjectIdentifiers.dilithium5);
            addSignatureAlgorithm(provider, "DILITHIUM2-AES", PREFIX + "SignatureSpi$Base2_AES", BCObjectIdentifiers.dilithium2_aes);
            addSignatureAlgorithm(provider, "DILITHIUM3-AES", PREFIX + "SignatureSpi$Base3_AES", BCObjectIdentifiers.dilithium3_aes);
            addSignatureAlgorithm(provider, "DILITHIUM5-AES", PREFIX + "SignatureSpi$Base5_AES", BCObjectIdentifiers.dilithium5_aes);

            AsymmetricKeyInfoConverter keyFact = new DilithiumKeyFactorySpi();

            registerKeyFactoryOid(provider, BCObjectIdentifiers.dilithium2, "DILITHIUM", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.dilithium3, "DILITHIUM", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.dilithium5, "DILITHIUM", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.dilithium2_aes, "DILITHIUM", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.dilithium3_aes, "DILITHIUM", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.dilithium5_aes, "DILITHIUM", keyFact);
        }
    }
}
