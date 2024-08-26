package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.MLDSAKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class MLDSA
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".mldsa.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.ML-DSA", PREFIX + "MLDSAKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.ML-DSA", PREFIX + "MLDSAKeyPairGeneratorSpi");

            addKeyFactoryAlgorithm(provider, "ML-DSA-44", PREFIX + "MLDSAKeyFactorySpi$MLDSA44", NISTObjectIdentifiers.id_ml_dsa_44, new MLDSAKeyFactorySpi.MLDSA44());
            addKeyFactoryAlgorithm(provider, "ML-DSA-65", PREFIX + "MLDSAKeyFactorySpi$MLDSA65", NISTObjectIdentifiers.id_ml_dsa_65, new MLDSAKeyFactorySpi.MLDSA65());
            addKeyFactoryAlgorithm(provider, "ML-DSA-87", PREFIX + "MLDSAKeyFactorySpi$MLDSA87", NISTObjectIdentifiers.id_ml_dsa_87, new MLDSAKeyFactorySpi.MLDSA87());

            addKeyPairGeneratorAlgorithm(provider, "ML-DSA-44", PREFIX + "MLDSAKeyPairGeneratorSpi$MLDSA44", NISTObjectIdentifiers.id_ml_dsa_44);
            addKeyPairGeneratorAlgorithm(provider, "ML-DSA-65", PREFIX + "MLDSAKeyPairGeneratorSpi$MLDSA65", NISTObjectIdentifiers.id_ml_dsa_65);
            addKeyPairGeneratorAlgorithm(provider, "ML-DSA-87", PREFIX + "MLDSAKeyPairGeneratorSpi$MLDSA87", NISTObjectIdentifiers.id_ml_dsa_87);

            addSignatureAlgorithm(provider, "ML-DSA", PREFIX + "SignatureSpi$MLDSA", (ASN1ObjectIdentifier) null);

            addSignatureAlgorithm(provider, "ML-DSA-44", PREFIX + "SignatureSpi$MLDSA44", NISTObjectIdentifiers.id_ml_dsa_44);
            addSignatureAlgorithm(provider, "ML-DSA-65", PREFIX + "SignatureSpi$MLDSA65", NISTObjectIdentifiers.id_ml_dsa_65);
            addSignatureAlgorithm(provider, "ML-DSA-87", PREFIX + "SignatureSpi$MLDSA87", NISTObjectIdentifiers.id_ml_dsa_87);


//            provider.addAlgorithm("Alg.Alias.Signature." + NISTObjectIdentifiers.id_ml_dsa_44, "ML-DSA");
//            provider.addAlgorithm("Alg.Alias.Signature.OID." + NISTObjectIdentifiers.id_ml_dsa_44, "ML-DSA");
//
//            provider.addAlgorithm("Alg.Alias.Signature." + NISTObjectIdentifiers.id_ml_dsa_65, "ML-DSA");
//            provider.addAlgorithm("Alg.Alias.Signature.OID." + NISTObjectIdentifiers.id_ml_dsa_65, "ML-DSA");
//
//            provider.addAlgorithm("Alg.Alias.Signature." + NISTObjectIdentifiers.id_ml_dsa_87, "ML-DSA");
//            provider.addAlgorithm("Alg.Alias.Signature.OID." + NISTObjectIdentifiers.id_ml_dsa_87, "ML-DSA");

            AsymmetricKeyInfoConverter keyFact = new MLDSAKeyFactorySpi();

            provider.addKeyInfoConverter(NISTObjectIdentifiers.id_ml_dsa_44, keyFact);
            provider.addKeyInfoConverter(NISTObjectIdentifiers.id_ml_dsa_65, keyFact);
            provider.addKeyInfoConverter(NISTObjectIdentifiers.id_ml_dsa_87, keyFact);
        }
    }
}
