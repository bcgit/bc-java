package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.provider.uov.UOVKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class UOV
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".uov.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.UOV", PREFIX + "UOVKeyFactorySpi$Generic");
            provider.addAlgorithm("KeyPairGenerator.UOV", PREFIX + "UOVKeyPairGeneratorSpi$Generic");
            addSignatureAlgorithm(provider, "UOV", PREFIX + "SignatureSpi$Generic", (ASN1ObjectIdentifier)null);

            AsymmetricKeyInfoConverter keyFact = new UOVKeyFactorySpi.Generic();

            addVariant(provider, "UOV-IS",         "Is",        BCObjectIdentifiers.uov_Is_classic, keyFact);
            addVariant(provider, "UOV-IS-PKC",     "IsPkc",     BCObjectIdentifiers.uov_Is_pkc, keyFact);
            addVariant(provider, "UOV-IS-PKC-SKC", "IsPkcSkc",  BCObjectIdentifiers.uov_Is_pkc_skc, keyFact);

            addVariant(provider, "UOV-IP",         "Ip",        BCObjectIdentifiers.uov_Ip_classic, keyFact);
            addVariant(provider, "UOV-IP-PKC",     "IpPkc",     BCObjectIdentifiers.uov_Ip_pkc, keyFact);
            addVariant(provider, "UOV-IP-PKC-SKC", "IpPkcSkc",  BCObjectIdentifiers.uov_Ip_pkc_skc, keyFact);

            addVariant(provider, "UOV-III",          "III",       BCObjectIdentifiers.uov_III_classic, keyFact);
            addVariant(provider, "UOV-III-PKC",      "IIIPkc",    BCObjectIdentifiers.uov_III_pkc, keyFact);
            addVariant(provider, "UOV-III-PKC-SKC",  "IIIPkcSkc", BCObjectIdentifiers.uov_III_pkc_skc, keyFact);

            addVariant(provider, "UOV-V",         "V",         BCObjectIdentifiers.uov_V_classic, keyFact);
            addVariant(provider, "UOV-V-PKC",     "VPkc",      BCObjectIdentifiers.uov_V_pkc, keyFact);
            addVariant(provider, "UOV-V-PKC-SKC", "VPkcSkc",   BCObjectIdentifiers.uov_V_pkc_skc, keyFact);
        }

        private void addVariant(ConfigurableProvider provider, String alg, String spiTag,
                                ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyFact)
        {
            addKeyFactoryAlgorithm(provider, alg, PREFIX + "UOVKeyFactorySpi$" + spiTag, oid, keyFact);
            addKeyPairGeneratorAlgorithm(provider, alg, PREFIX + "UOVKeyPairGeneratorSpi$" + spiTag, oid);
            addSignatureAlgorithm(provider, alg, PREFIX + "SignatureSpi$" + spiTag, oid);
        }
    }
}
