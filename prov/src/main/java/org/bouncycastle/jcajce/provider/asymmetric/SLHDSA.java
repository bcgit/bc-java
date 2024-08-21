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
            provider.addAlgorithm("KeyFactory.SLH-DSA", PREFIX + "SLHDSAKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SLH-DSA", PREFIX + "SLHDSAKeyPairGeneratorSpi");

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
            
            addSignatureAlgorithm(provider, "SLH-DSA", PREFIX + "SignatureSpi$Direct", (ASN1ObjectIdentifier)null);

            ASN1ObjectIdentifier[] nistOids = new ASN1ObjectIdentifier[]
            {
                NISTObjectIdentifiers.id_slh_dsa_sha2_128s,
                NISTObjectIdentifiers.id_slh_dsa_sha2_128f,
                NISTObjectIdentifiers.id_slh_dsa_shake_128s,
                NISTObjectIdentifiers.id_slh_dsa_shake_128f,
                NISTObjectIdentifiers.id_slh_dsa_sha2_192s,
                NISTObjectIdentifiers.id_slh_dsa_sha2_192f,
                NISTObjectIdentifiers.id_slh_dsa_shake_192s,
                NISTObjectIdentifiers.id_slh_dsa_shake_192f,
                NISTObjectIdentifiers.id_slh_dsa_sha2_256s,
                NISTObjectIdentifiers.id_slh_dsa_sha2_256f,
                NISTObjectIdentifiers.id_slh_dsa_shake_256s,
                NISTObjectIdentifiers.id_slh_dsa_shake_256f
            };
            
            for (int i = 0; i != nistOids.length; i++)
            {
                provider.addAlgorithm("Alg.Alias.Signature." + nistOids[i], "SLH-DSA");
                provider.addAlgorithm("Alg.Alias.Signature.OID." + nistOids[i], "SLH-DSA");
            }

            AsymmetricKeyInfoConverter keyFact = new SLHDSAKeyFactorySpi();

            registerKeyFactoryOid(provider, NISTObjectIdentifiers.id_slh_dsa_sha2_128s, "SLH-DSA", keyFact);
            registerKeyFactoryOid(provider, NISTObjectIdentifiers.id_slh_dsa_sha2_128f, "SLH-DSA", keyFact);
            registerKeyFactoryOid(provider, NISTObjectIdentifiers.id_slh_dsa_sha2_192s, "SLH-DSA", keyFact);
            registerKeyFactoryOid(provider, NISTObjectIdentifiers.id_slh_dsa_sha2_192f, "SLH-DSA", keyFact);
            registerKeyFactoryOid(provider, NISTObjectIdentifiers.id_slh_dsa_sha2_256s, "SLH-DSA", keyFact);
            registerKeyFactoryOid(provider, NISTObjectIdentifiers.id_slh_dsa_sha2_256f, "SLH-DSA", keyFact);
            registerKeyFactoryOid(provider, NISTObjectIdentifiers.id_slh_dsa_shake_128s, "SLH-DSA", keyFact);
            registerKeyFactoryOid(provider, NISTObjectIdentifiers.id_slh_dsa_shake_128f, "SLH-DSA", keyFact);
            registerKeyFactoryOid(provider, NISTObjectIdentifiers.id_slh_dsa_shake_192s, "SLH-DSA", keyFact);
            registerKeyFactoryOid(provider, NISTObjectIdentifiers.id_slh_dsa_shake_192f, "SLH-DSA", keyFact);
            registerKeyFactoryOid(provider, NISTObjectIdentifiers.id_slh_dsa_shake_256s, "SLH-DSA", keyFact);
            registerKeyFactoryOid(provider, NISTObjectIdentifiers.id_slh_dsa_shake_256f, "SLH-DSA", keyFact);
        }
    }
}
