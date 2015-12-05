package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.dh.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class DH
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".dh.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyPairGenerator.DH", PREFIX + "KeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.DIFFIEHELLMAN", "DH");

            provider.addAlgorithm("KeyAgreement.DH", PREFIX + "KeyAgreementSpi");
            provider.addAlgorithm("Alg.Alias.KeyAgreement.DIFFIEHELLMAN", "DH");
            provider.addAlgorithm("KeyAgreement", PKCSObjectIdentifiers.id_alg_ESDH, PREFIX + "KeyAgreementSpi$DHwithRFC2631KDF");
            provider.addAlgorithm("KeyAgreement", PKCSObjectIdentifiers.id_alg_SSDH, PREFIX + "KeyAgreementSpi$DHwithRFC2631KDF");

            provider.addAlgorithm("KeyFactory.DH", PREFIX + "KeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.DIFFIEHELLMAN", "DH");

            provider.addAlgorithm("AlgorithmParameters.DH", PREFIX + "AlgorithmParametersSpi");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.DIFFIEHELLMAN", "DH");

            provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator.DIFFIEHELLMAN", "DH");

            provider.addAlgorithm("AlgorithmParameterGenerator.DH", PREFIX + "AlgorithmParameterGeneratorSpi");

            provider.addAlgorithm("Cipher.IES", PREFIX + "IESCipher$IES");
            provider.addAlgorithm("Cipher.IESwithAES", PREFIX + "IESCipher$IESwithAES");
            provider.addAlgorithm("Cipher.IESWITHAES", PREFIX + "IESCipher$IESwithAES");
            provider.addAlgorithm("Cipher.IESWITHDESEDE", PREFIX + "IESCipher$IESwithDESede");

            provider.addAlgorithm("Cipher.DHIES", PREFIX + "IESCipher$IES");
            provider.addAlgorithm("Cipher.DHIESwithAES", PREFIX + "IESCipher$IESwithAES");
            provider.addAlgorithm("Cipher.DHIESWITHAES", PREFIX + "IESCipher$IESwithAES");
            provider.addAlgorithm("Cipher.DHIESWITHDESEDE", PREFIX + "IESCipher$IESwithDESede");

            provider.addAlgorithm("Cipher.OLDDHIES", PREFIX + "IESCipher$OldIES");
            provider.addAlgorithm("Cipher.OLDDHIESwithAES", PREFIX + "IESCipher$OldIESwithAES");
            provider.addAlgorithm("Cipher.OLDDHIESWITHAES", PREFIX + "IESCipher$OldIESwithAES");
            provider.addAlgorithm("Cipher.OLDDHIESWITHDESEDE", PREFIX + "IESCipher$OldIESwithDESede");

            registerOid(provider, PKCSObjectIdentifiers.dhKeyAgreement, "DH", new KeyFactorySpi());
            registerOid(provider, X9ObjectIdentifiers.dhpublicnumber, "DH", new KeyFactorySpi());
        }
    }
}
