package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class SLHDSA
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".slhdsa.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.SLH-DSA", PREFIX + "SLHDSAKeyFactorySpi$Pure");
            provider.addAlgorithm("KeyPairGenerator.SLH-DSA", PREFIX + "SLHDSAKeyPairGeneratorSpi$Pure");
            provider.addAlgorithm("KeyFactory.HASH-SLH-DSA", PREFIX + "SLHDSAKeyFactorySpi$Hash");
            provider.addAlgorithm("KeyPairGenerator.HASH-SLH-DSA", PREFIX + "SLHDSAKeyPairGeneratorSpi$Hash");

            AsymmetricKeyInfoConverter keyFact = new SLHDSAKeyFactorySpi.Hash();

            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHA2-128S", PREFIX + "SLHDSAKeyFactorySpi$Sha2_128s", NISTObjectIdentifiers.id_slh_dsa_sha2_128s, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHA2-128F", PREFIX + "SLHDSAKeyFactorySpi$Sha2_128f", NISTObjectIdentifiers.id_slh_dsa_sha2_128f, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHA2-192S", PREFIX + "SLHDSAKeyFactorySpi$Sha2_192s", NISTObjectIdentifiers.id_slh_dsa_sha2_192s, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHA2-192F", PREFIX + "SLHDSAKeyFactorySpi$Sha2_192f", NISTObjectIdentifiers.id_slh_dsa_sha2_192f, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHA2-256S", PREFIX + "SLHDSAKeyFactorySpi$Sha2_256s", NISTObjectIdentifiers.id_slh_dsa_sha2_256s, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHA2-256F", PREFIX + "SLHDSAKeyFactorySpi$Sha2_256f", NISTObjectIdentifiers.id_slh_dsa_sha2_256f, keyFact);

            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHAKE-128S", PREFIX + "SLHDSAKeyFactorySpi$Shake_128s", NISTObjectIdentifiers.id_slh_dsa_shake_128s, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHAKE-128F", PREFIX + "SLHDSAKeyFactorySpi$Shake_128f", NISTObjectIdentifiers.id_slh_dsa_shake_128f, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHAKE-192S", PREFIX + "SLHDSAKeyFactorySpi$Shake_192s", NISTObjectIdentifiers.id_slh_dsa_shake_192s, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHAKE-192F", PREFIX + "SLHDSAKeyFactorySpi$Shake_192f", NISTObjectIdentifiers.id_slh_dsa_shake_192f, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHAKE-256S", PREFIX + "SLHDSAKeyFactorySpi$Shake_256s", NISTObjectIdentifiers.id_slh_dsa_shake_256s, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHAKE-256F", PREFIX + "SLHDSAKeyFactorySpi$Shake_256f", NISTObjectIdentifiers.id_slh_dsa_shake_256f, keyFact);

            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHA2-128S-WITH-SHA256", PREFIX + "SLHDSAKeyFactorySpi$HashSha2_128s", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHA2-128F-WITH-SHA256", PREFIX + "SLHDSAKeyFactorySpi$HashSha2_128f", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHA2-192S-WITH-SHA512", PREFIX + "SLHDSAKeyFactorySpi$HashSha2_192s", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHA2-192F-WITH-SHA512", PREFIX + "SLHDSAKeyFactorySpi$HashSha2_192f", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHA2-256S-WITH-SHA512", PREFIX + "SLHDSAKeyFactorySpi$HashSha2_256s", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHA2-256F-WITH-SHA512", PREFIX + "SLHDSAKeyFactorySpi$HashSha2_256f", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512, keyFact);

            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHAKE-128S-WITH-SHAKE128", PREFIX + "SLHDSAKeyFactorySpi$HashShake_128s", NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHAKE-128F-WITH-SHAKE128", PREFIX + "SLHDSAKeyFactorySpi$HashShake_128f", NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHAKE-192S-WITH-SHAKE256", PREFIX + "SLHDSAKeyFactorySpi$HashShake_192s", NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHAKE-192F-WITH-SHAKE256", PREFIX + "SLHDSAKeyFactorySpi$HashShake_192f", NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHAKE-256S-WITH-SHAKE256", PREFIX + "SLHDSAKeyFactorySpi$HashShake_256s", NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256, keyFact);
            addKeyFactoryAlgorithm(provider, "SLH-DSA-SHAKE-256F-WITH-SHAKE256", PREFIX + "SLHDSAKeyFactorySpi$HashShake_256f", NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256, keyFact);

            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHA2-128S", PREFIX + "SLHDSAKeyPairGeneratorSpi$Sha2_128s", NISTObjectIdentifiers.id_slh_dsa_sha2_128s);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHA2-128F", PREFIX + "SLHDSAKeyPairGeneratorSpi$Sha2_128f", NISTObjectIdentifiers.id_slh_dsa_sha2_128f);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHA2-192S", PREFIX + "SLHDSAKeyPairGeneratorSpi$Sha2_192s", NISTObjectIdentifiers.id_slh_dsa_sha2_192s);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHA2-192F", PREFIX + "SLHDSAKeyPairGeneratorSpi$Sha2_192f", NISTObjectIdentifiers.id_slh_dsa_sha2_192f);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHA2-256S", PREFIX + "SLHDSAKeyPairGeneratorSpi$Sha2_256s", NISTObjectIdentifiers.id_slh_dsa_sha2_256s);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHA2-256F", PREFIX + "SLHDSAKeyPairGeneratorSpi$Sha2_256f", NISTObjectIdentifiers.id_slh_dsa_sha2_256f);

            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHAKE-128S", PREFIX + "SLHDSAKeyPairGeneratorSpi$Shake_128s", NISTObjectIdentifiers.id_slh_dsa_shake_128s);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHAKE-128F", PREFIX + "SLHDSAKeyPairGeneratorSpi$Shake_128f", NISTObjectIdentifiers.id_slh_dsa_shake_128f);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHAKE-192S", PREFIX + "SLHDSAKeyPairGeneratorSpi$Shake_192s", NISTObjectIdentifiers.id_slh_dsa_shake_192s);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHAKE-192F", PREFIX + "SLHDSAKeyPairGeneratorSpi$Shake_192f", NISTObjectIdentifiers.id_slh_dsa_shake_192f);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHAKE-256S", PREFIX + "SLHDSAKeyPairGeneratorSpi$Shake_256s", NISTObjectIdentifiers.id_slh_dsa_shake_256s);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHAKE-256F", PREFIX + "SLHDSAKeyPairGeneratorSpi$Shake_256f", NISTObjectIdentifiers.id_slh_dsa_shake_256f);

            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHA2-128S-WITH-SHA256", PREFIX + "SLHDSAKeyPairGeneratorSpi$HashSha2_128s", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHA2-128F-WITH-SHA256", PREFIX + "SLHDSAKeyPairGeneratorSpi$HashSha2_128f", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHA2-192S-WITH-SHA512", PREFIX + "SLHDSAKeyPairGeneratorSpi$HashSha2_192s", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHA2-192F-WITH-SHA512", PREFIX + "SLHDSAKeyPairGeneratorSpi$HashSha2_192f", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHA2-256S-WITH-SHA512", PREFIX + "SLHDSAKeyPairGeneratorSpi$HashSha2_256s", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHA2-256F-WITH-SHA512", PREFIX + "SLHDSAKeyPairGeneratorSpi$HashSha2_256f", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512);

            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHAKE-128S-WITH-SHAKE128", PREFIX + "SLHDSAKeyPairGeneratorSpi$HashShake_128s", NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHAKE-128F-WITH-SHAKE128", PREFIX + "SLHDSAKeyPairGeneratorSpi$HashShake_128f", NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHAKE-192S-WITH-SHAKE256", PREFIX + "SLHDSAKeyPairGeneratorSpi$HashShake_192s", NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHAKE-192F-WITH-SHAKE256", PREFIX + "SLHDSAKeyPairGeneratorSpi$HashShake_192f", NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHAKE-256S-WITH-SHAKE256", PREFIX + "SLHDSAKeyPairGeneratorSpi$HashShake_256s", NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256);
            addKeyPairGeneratorAlgorithm(provider, "SLH-DSA-SHAKE-256F-WITH-SHAKE256", PREFIX + "SLHDSAKeyPairGeneratorSpi$HashShake_256f", NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256);

            String[] algNames = new String[]
                {
                    "SLH-DSA-SHA2-128S",
                    "SLH-DSA-SHA2-128F",
                    "SLH-DSA-SHA2-192S",
                    "SLH-DSA-SHA2-192F",
                    "SLH-DSA-SHA2-256S",
                    "SLH-DSA-SHA2-256F",
                    "SLH-DSA-SHAKE-128S",
                    "SLH-DSA-SHAKE-128F",
                    "SLH-DSA-SHAKE-192S",
                    "SLH-DSA-SHAKE-192F",
                    "SLH-DSA-SHAKE-256S",
                    "SLH-DSA-SHAKE-256F"
                };

            String[] hashAlgNames = new String[]
                {
                    "SLH-DSA-SHA2-128S-WITH-SHA256",
                    "SLH-DSA-SHA2-128F-WITH-SHA256",
                    "SLH-DSA-SHA2-192S-WITH-SHA512",
                    "SLH-DSA-SHA2-192F-WITH-SHA512",
                    "SLH-DSA-SHA2-256S-WITH-SHA512",
                    "SLH-DSA-SHA2-256F-WITH-SHA512",
                    "SLH-DSA-SHAKE-128S-WITH-SHAKE128",
                    "SLH-DSA-SHAKE-128F-WITH-SHAKE128",
                    "SLH-DSA-SHAKE-192S-WITH-SHAKE256",
                    "SLH-DSA-SHAKE-192F-WITH-SHAKE256",
                    "SLH-DSA-SHAKE-256S-WITH-SHAKE256",
                    "SLH-DSA-SHAKE-256F-WITH-SHAKE256"
                };

            addSignatureAlgorithm(provider, "SLH-DSA", PREFIX + "SignatureSpi$Direct", (ASN1ObjectIdentifier)null);
            provider.addAlgorithm("Alg.Alias.Signature.SLHDSA", "SLH-DSA");
            addSignatureAlgorithm(provider, "HASH-SLH-DSA", PREFIX + "HashSignatureSpi$Direct", (ASN1ObjectIdentifier)null);
            provider.addAlgorithm("Alg.Alias.Signature.HASHWITHSLHDSA", "HASH-SLH-DSA");

            for (int i = 0; i != algNames.length; i++)
            {
                provider.addAlgorithm("Alg.Alias.Signature." + algNames[i], "SLH-DSA");
            }

            for (int i = 0; i != hashAlgNames.length; i++)
            {
                provider.addAlgorithm("Alg.Alias.Signature." + hashAlgNames[i], "HASH-SLH-DSA");
            }

            ASN1ObjectIdentifier[] nistOids = new ASN1ObjectIdentifier[]
                {
                    NISTObjectIdentifiers.id_slh_dsa_sha2_128s,
                    NISTObjectIdentifiers.id_slh_dsa_sha2_128f,
                    NISTObjectIdentifiers.id_slh_dsa_sha2_192s,
                    NISTObjectIdentifiers.id_slh_dsa_sha2_192f,
                    NISTObjectIdentifiers.id_slh_dsa_sha2_256s,
                    NISTObjectIdentifiers.id_slh_dsa_sha2_256f,
                    NISTObjectIdentifiers.id_slh_dsa_shake_128s,
                    NISTObjectIdentifiers.id_slh_dsa_shake_128f,
                    NISTObjectIdentifiers.id_slh_dsa_shake_192s,
                    NISTObjectIdentifiers.id_slh_dsa_shake_192f,
                    NISTObjectIdentifiers.id_slh_dsa_shake_256s,
                    NISTObjectIdentifiers.id_slh_dsa_shake_256f
                };

            for (int i = 0; i != nistOids.length; i++)
            {
                provider.addAlgorithm("Alg.Alias.Signature." + nistOids[i], "SLH-DSA");
                provider.addAlgorithm("Alg.Alias.Signature.OID." + nistOids[i], "SLH-DSA");
            }

            nistOids = new ASN1ObjectIdentifier[]
                {
                    NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256,
                    NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256,
                    NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128,
                    NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128,
                    NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512,
                    NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512,
                    NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256,
                    NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256,
                    NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512,
                    NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512,
                    NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256,
                    NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256
                };

            for (int i = 0; i != nistOids.length; i++)
            {
                provider.addAlgorithm("Alg.Alias.Signature." + nistOids[i], "HASH-SLH-DSA");
                provider.addAlgorithm("Alg.Alias.Signature.OID." + nistOids[i], "HASH-SLH-DSA");
            }
        }
    }
}
