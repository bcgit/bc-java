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
            provider.addAlgorithm("KeyFactory.ML-DSA", PREFIX + "MLDSAKeyFactorySpi$Pure");
            provider.addAlgorithm("KeyPairGenerator.ML-DSA", PREFIX + "MLDSAKeyPairGeneratorSpi$Pure");
            provider.addAlgorithm("Alg.Alias.KeyFactory.MLDSA", "ML-DSA");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.MLDSA", "ML-DSA");
            provider.addAlgorithm("KeyFactory.HASH-ML-DSA", PREFIX + "MLDSAKeyFactorySpi$Hash");
            provider.addAlgorithm("KeyPairGenerator.HASH-ML-DSA", PREFIX + "MLDSAKeyPairGeneratorSpi$Hash");
            provider.addAlgorithm("Alg.Alias.KeyFactory.SHA512WITHMLDSA", "HASH-ML-DSA");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.SHA512WITHMLDSA", "HASH-ML-DSA");

            addKeyFactoryAlgorithm(provider, "ML-DSA-44", PREFIX + "MLDSAKeyFactorySpi$MLDSA44", NISTObjectIdentifiers.id_ml_dsa_44, new MLDSAKeyFactorySpi.MLDSA44());
            addKeyFactoryAlgorithm(provider, "ML-DSA-65", PREFIX + "MLDSAKeyFactorySpi$MLDSA65", NISTObjectIdentifiers.id_ml_dsa_65, new MLDSAKeyFactorySpi.MLDSA65());
            addKeyFactoryAlgorithm(provider, "ML-DSA-87", PREFIX + "MLDSAKeyFactorySpi$MLDSA87", NISTObjectIdentifiers.id_ml_dsa_87, new MLDSAKeyFactorySpi.MLDSA87());
            addKeyFactoryAlgorithm(provider, "ML-DSA-44-WITH-SHA512", PREFIX + "MLDSAKeyFactorySpi$HashMLDSA44", NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512, new MLDSAKeyFactorySpi.HashMLDSA44());
            addKeyFactoryAlgorithm(provider, "ML-DSA-65-WITH-SHA512", PREFIX + "MLDSAKeyFactorySpi$HashMLDSA65", NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512, new MLDSAKeyFactorySpi.HashMLDSA65());
            addKeyFactoryAlgorithm(provider, "ML-DSA-87-WITH-SHA512", PREFIX + "MLDSAKeyFactorySpi$HashMLDSA87", NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512, new MLDSAKeyFactorySpi.HashMLDSA87());

            addKeyPairGeneratorAlgorithm(provider, "ML-DSA-44", PREFIX + "MLDSAKeyPairGeneratorSpi$MLDSA44", NISTObjectIdentifiers.id_ml_dsa_44);
            addKeyPairGeneratorAlgorithm(provider, "ML-DSA-65", PREFIX + "MLDSAKeyPairGeneratorSpi$MLDSA65", NISTObjectIdentifiers.id_ml_dsa_65);
            addKeyPairGeneratorAlgorithm(provider, "ML-DSA-87", PREFIX + "MLDSAKeyPairGeneratorSpi$MLDSA87", NISTObjectIdentifiers.id_ml_dsa_87);
            addKeyPairGeneratorAlgorithm(provider, "ML-DSA-44-WITH-SHA512", PREFIX + "MLDSAKeyPairGeneratorSpi$MLDSA44withSHA512", NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512);
            addKeyPairGeneratorAlgorithm(provider, "ML-DSA-65-WITH-SHA512", PREFIX + "MLDSAKeyPairGeneratorSpi$MLDSA65withSHA512", NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512);
            addKeyPairGeneratorAlgorithm(provider, "ML-DSA-87-WITH-SHA512", PREFIX + "MLDSAKeyPairGeneratorSpi$MLDSA87withSHA512", NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512);

            addSignatureAlgorithm(provider, "ML-DSA", PREFIX + "SignatureSpi$MLDSA", (ASN1ObjectIdentifier)null);
            addSignatureAlgorithm(provider, "ML-DSA-44", PREFIX + "SignatureSpi$MLDSA44", NISTObjectIdentifiers.id_ml_dsa_44);
            addSignatureAlgorithm(provider, "ML-DSA-65", PREFIX + "SignatureSpi$MLDSA65", NISTObjectIdentifiers.id_ml_dsa_65);
            addSignatureAlgorithm(provider, "ML-DSA-87", PREFIX + "SignatureSpi$MLDSA87", NISTObjectIdentifiers.id_ml_dsa_87);
            provider.addAlgorithm("Alg.Alias.Signature.MLDSA", "ML-DSA");

            addSignatureAlgorithm(provider, "ML-DSA-CALCULATE-MU", PREFIX + "SignatureSpi$MLDSACalcMu", (ASN1ObjectIdentifier)null);
            provider.addAlgorithm("Alg.Alias.Signature.MLDSA-CALCULATE-MU", "ML-DSA-CALCULATE-MU");

            addSignatureAlgorithm(provider, "ML-DSA-EXTERNAL-MU", PREFIX + "SignatureSpi$MLDSAExtMu", (ASN1ObjectIdentifier)null);
            provider.addAlgorithm("Alg.Alias.Signature.MLDSA-EXTERNAL-MU", "ML-DSA-EXTERNAL-MU");

            addSignatureAlgorithm(provider, "HASH-ML-DSA", PREFIX + "HashSignatureSpi$MLDSA", (ASN1ObjectIdentifier)null);
            addSignatureAlgorithm(provider, "ML-DSA-44-WITH-SHA512", PREFIX + "HashSignatureSpi$MLDSA44", NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512);
            addSignatureAlgorithm(provider, "ML-DSA-65-WITH-SHA512", PREFIX + "HashSignatureSpi$MLDSA65", NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512);
            addSignatureAlgorithm(provider, "ML-DSA-87-WITH-SHA512", PREFIX + "HashSignatureSpi$MLDSA87", NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512);

            // External-hash variants: caller pre-hashes the message and feeds the
            // digest to Signature.update(...). See github #2198.
            addSignatureAlgorithm(provider, "HASH-ML-DSA-EXTERNAL-HASH", PREFIX + "HashSignatureSpi$MLDSAExtHash", (ASN1ObjectIdentifier)null);
            addSignatureAlgorithm(provider, "ML-DSA-44-WITH-SHA512-EXTERNAL-HASH", PREFIX + "HashSignatureSpi$MLDSA44ExtHash", (ASN1ObjectIdentifier)null);
            addSignatureAlgorithm(provider, "ML-DSA-65-WITH-SHA512-EXTERNAL-HASH", PREFIX + "HashSignatureSpi$MLDSA65ExtHash", (ASN1ObjectIdentifier)null);
            addSignatureAlgorithm(provider, "ML-DSA-87-WITH-SHA512-EXTERNAL-HASH", PREFIX + "HashSignatureSpi$MLDSA87ExtHash", (ASN1ObjectIdentifier)null);

            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHMLDSA", "HASH-ML-DSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHMLDSA44", "ML-DSA-44-WITH-SHA512");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHMLDSA65", "ML-DSA-65-WITH-SHA512");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHMLDSA87", "ML-DSA-87-WITH-SHA512");
            provider.addAlgorithm("Alg.Alias.Signature.MLDSA-EXTERNAL-HASH", "HASH-ML-DSA-EXTERNAL-HASH");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHMLDSA44EXTERNALHASH", "ML-DSA-44-WITH-SHA512-EXTERNAL-HASH");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHMLDSA65EXTERNALHASH", "ML-DSA-65-WITH-SHA512-EXTERNAL-HASH");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHMLDSA87EXTERNALHASH", "ML-DSA-87-WITH-SHA512-EXTERNAL-HASH");

            AsymmetricKeyInfoConverter keyFact = new MLDSAKeyFactorySpi.Hash();

            provider.addKeyInfoConverter(NISTObjectIdentifiers.id_ml_dsa_44, keyFact);
            provider.addKeyInfoConverter(NISTObjectIdentifiers.id_ml_dsa_65, keyFact);
            provider.addKeyInfoConverter(NISTObjectIdentifiers.id_ml_dsa_87, keyFact);
            provider.addKeyInfoConverter(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512, keyFact);
            provider.addKeyInfoConverter(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512, keyFact);
            provider.addKeyInfoConverter(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512, keyFact);
        }
    }
}
