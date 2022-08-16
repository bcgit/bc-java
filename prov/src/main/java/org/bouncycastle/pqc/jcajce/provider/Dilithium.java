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

            provider.addAlgorithm("KeyGenerator.DILITHIUM", PREFIX + "DilithiumKeyGeneratorSpi");

            addSignatureAlgorithm(provider, "DILITHIUM", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.dilithium);

            addSignatureAlgorithm(provider, "DILITHIUM2", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.dilithium2);
            addSignatureAlgorithm(provider, "DILITHIUM3", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.dilithium3);
            addSignatureAlgorithm(provider, "DILITHIUM5", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.dilithium5);

            AsymmetricKeyInfoConverter keyFact = new DilithiumKeyFactorySpi();

            registerOid(provider, BCObjectIdentifiers.dilithium2, "Dilithium", keyFact);
            registerOid(provider, BCObjectIdentifiers.dilithium3, "Dilithium", keyFact);
            registerOid(provider, BCObjectIdentifiers.dilithium5, "Dilithium", keyFact);
        }
    }
}
