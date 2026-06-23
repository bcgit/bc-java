package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.internal.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.cmce.CMCEKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class CMCE
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".cmce.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.CMCE", PREFIX + "CMCEKeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.CMCE", "CMCE");

            addKeyFactoryAlgorithm(provider, "mceliece460896", PREFIX + "CMCEKeyFactorySpi$Mceliece460896", ISOIECObjectIdentifiers.mceliece460896, new CMCEKeyFactorySpi.Mceliece460896());
            addKeyFactoryAlgorithm(provider, "mceliece460896f", PREFIX + "CMCEKeyFactorySpi$Mceliece460896F", ISOIECObjectIdentifiers.mceliece460896f, new CMCEKeyFactorySpi.Mceliece460896F());
            addKeyFactoryAlgorithm(provider, "mceliece460896pc", PREFIX + "CMCEKeyFactorySpi$Mceliece460896Pc", ISOIECObjectIdentifiers.mceliece460896pc, new CMCEKeyFactorySpi.Mceliece460896Pc());
            addKeyFactoryAlgorithm(provider, "mceliece460896pcf", PREFIX + "CMCEKeyFactorySpi$Mceliece460896Pcf", ISOIECObjectIdentifiers.mceliece460896pcf, new CMCEKeyFactorySpi.Mceliece460896Pcf());
            addKeyFactoryAlgorithm(provider, "mceliece6688128", PREFIX + "CMCEKeyFactorySpi$Mceliece6688128", ISOIECObjectIdentifiers.mceliece6688128, new CMCEKeyFactorySpi.Mceliece6688128());
            addKeyFactoryAlgorithm(provider, "mceliece6688128f", PREFIX + "CMCEKeyFactorySpi$Mceliece6688128F", ISOIECObjectIdentifiers.mceliece6688128f, new CMCEKeyFactorySpi.Mceliece6688128F());
            addKeyFactoryAlgorithm(provider, "mceliece6688128pc", PREFIX + "CMCEKeyFactorySpi$Mceliece6688128Pc", ISOIECObjectIdentifiers.mceliece6688128pc, new CMCEKeyFactorySpi.Mceliece6688128Pc());
            addKeyFactoryAlgorithm(provider, "mceliece6688128pcf", PREFIX + "CMCEKeyFactorySpi$Mceliece6688128Pcf", ISOIECObjectIdentifiers.mceliece6688128pcf, new CMCEKeyFactorySpi.Mceliece6688128Pcf());
            addKeyFactoryAlgorithm(provider, "mceliece6960119", PREFIX + "CMCEKeyFactorySpi$Mceliece6960119", ISOIECObjectIdentifiers.mceliece6960119, new CMCEKeyFactorySpi.Mceliece6960119());
            addKeyFactoryAlgorithm(provider, "mceliece6960119f", PREFIX + "CMCEKeyFactorySpi$Mceliece6960119F", ISOIECObjectIdentifiers.mceliece6960119f, new CMCEKeyFactorySpi.Mceliece6960119F());
            addKeyFactoryAlgorithm(provider, "mceliece6960119pc", PREFIX + "CMCEKeyFactorySpi$Mceliece6960119Pc", ISOIECObjectIdentifiers.mceliece6960119pc, new CMCEKeyFactorySpi.Mceliece6960119Pc());
            addKeyFactoryAlgorithm(provider, "mceliece6960119pcf", PREFIX + "CMCEKeyFactorySpi$Mceliece6960119Pcf", ISOIECObjectIdentifiers.mceliece6960119pcf, new CMCEKeyFactorySpi.Mceliece6960119Pcf());
            addKeyFactoryAlgorithm(provider, "mceliece8192128", PREFIX + "CMCEKeyFactorySpi$Mceliece8192128", ISOIECObjectIdentifiers.mceliece8192128, new CMCEKeyFactorySpi.Mceliece8192128());
            addKeyFactoryAlgorithm(provider, "mceliece8192128f", PREFIX + "CMCEKeyFactorySpi$Mceliece8192128F", ISOIECObjectIdentifiers.mceliece8192128f, new CMCEKeyFactorySpi.Mceliece8192128F());
            addKeyFactoryAlgorithm(provider, "mceliece8192128pc", PREFIX + "CMCEKeyFactorySpi$Mceliece8192128Pc", ISOIECObjectIdentifiers.mceliece8192128pc, new CMCEKeyFactorySpi.Mceliece8192128Pc());
            addKeyFactoryAlgorithm(provider, "mceliece8192128pcf", PREFIX + "CMCEKeyFactorySpi$Mceliece8192128Pcf", ISOIECObjectIdentifiers.mceliece8192128pcf, new CMCEKeyFactorySpi.Mceliece8192128Pcf());

            provider.addAlgorithm("KeyPairGenerator.CMCE", PREFIX + "CMCEKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.CMCE", "CMCE");

            addKeyPairGeneratorAlgorithm(provider, "mceliece460896", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece460896", ISOIECObjectIdentifiers.mceliece460896);
            addKeyPairGeneratorAlgorithm(provider, "mceliece460896f", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece460896F", ISOIECObjectIdentifiers.mceliece460896f);
            addKeyPairGeneratorAlgorithm(provider, "mceliece460896pc", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece460896Pc", ISOIECObjectIdentifiers.mceliece460896pc);
            addKeyPairGeneratorAlgorithm(provider, "mceliece460896pcf", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece460896Pcf", ISOIECObjectIdentifiers.mceliece460896pcf);
            addKeyPairGeneratorAlgorithm(provider, "mceliece6688128", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece6688128", ISOIECObjectIdentifiers.mceliece6688128);
            addKeyPairGeneratorAlgorithm(provider, "mceliece6688128f", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece6688128F", ISOIECObjectIdentifiers.mceliece6688128f);
            addKeyPairGeneratorAlgorithm(provider, "mceliece6688128pc", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece6688128Pc", ISOIECObjectIdentifiers.mceliece6688128pc);
            addKeyPairGeneratorAlgorithm(provider, "mceliece6688128pcf", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece6688128Pcf", ISOIECObjectIdentifiers.mceliece6688128pcf);
            addKeyPairGeneratorAlgorithm(provider, "mceliece6960119", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece6960119", ISOIECObjectIdentifiers.mceliece6960119);
            addKeyPairGeneratorAlgorithm(provider, "mceliece6960119f", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece6960119F", ISOIECObjectIdentifiers.mceliece6960119f);
            addKeyPairGeneratorAlgorithm(provider, "mceliece6960119pc", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece6960119Pc", ISOIECObjectIdentifiers.mceliece6960119pc);
            addKeyPairGeneratorAlgorithm(provider, "mceliece6960119pcf", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece6960119Pcf", ISOIECObjectIdentifiers.mceliece6960119pcf);
            addKeyPairGeneratorAlgorithm(provider, "mceliece8192128", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece8192128", ISOIECObjectIdentifiers.mceliece8192128);
            addKeyPairGeneratorAlgorithm(provider, "mceliece8192128f", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece8192128F", ISOIECObjectIdentifiers.mceliece8192128f);
            addKeyPairGeneratorAlgorithm(provider, "mceliece8192128pc", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece8192128Pc", ISOIECObjectIdentifiers.mceliece8192128pc);
            addKeyPairGeneratorAlgorithm(provider, "mceliece8192128pcf", PREFIX + "CMCEKeyPairGeneratorSpi$Mceliece8192128Pcf", ISOIECObjectIdentifiers.mceliece8192128pcf);

            provider.addAlgorithm("KeyGenerator.CMCE", PREFIX + "CMCEKeyGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyGenerator.CMCE", "CMCE");

            addKeyGeneratorAlgorithm(provider, "mceliece460896", PREFIX + "CMCEKeyGeneratorSpi$Mceliece460896", ISOIECObjectIdentifiers.mceliece460896);
            addKeyGeneratorAlgorithm(provider, "mceliece460896f", PREFIX + "CMCEKeyGeneratorSpi$Mceliece460896F", ISOIECObjectIdentifiers.mceliece460896f);
            addKeyGeneratorAlgorithm(provider, "mceliece460896pc", PREFIX + "CMCEKeyGeneratorSpi$Mceliece460896Pc", ISOIECObjectIdentifiers.mceliece460896pc);
            addKeyGeneratorAlgorithm(provider, "mceliece460896pcf", PREFIX + "CMCEKeyGeneratorSpi$Mceliece460896Pcf", ISOIECObjectIdentifiers.mceliece460896pcf);
            addKeyGeneratorAlgorithm(provider, "mceliece6688128", PREFIX + "CMCEKeyGeneratorSpi$Mceliece6688128", ISOIECObjectIdentifiers.mceliece6688128);
            addKeyGeneratorAlgorithm(provider, "mceliece6688128f", PREFIX + "CMCEKeyGeneratorSpi$Mceliece6688128F", ISOIECObjectIdentifiers.mceliece6688128f);
            addKeyGeneratorAlgorithm(provider, "mceliece6688128pc", PREFIX + "CMCEKeyGeneratorSpi$Mceliece6688128Pc", ISOIECObjectIdentifiers.mceliece6688128pc);
            addKeyGeneratorAlgorithm(provider, "mceliece6688128pcf", PREFIX + "CMCEKeyGeneratorSpi$Mceliece6688128Pcf", ISOIECObjectIdentifiers.mceliece6688128pcf);
            addKeyGeneratorAlgorithm(provider, "mceliece6960119", PREFIX + "CMCEKeyGeneratorSpi$Mceliece6960119", ISOIECObjectIdentifiers.mceliece6960119);
            addKeyGeneratorAlgorithm(provider, "mceliece6960119f", PREFIX + "CMCEKeyGeneratorSpi$Mceliece6960119F", ISOIECObjectIdentifiers.mceliece6960119f);
            addKeyGeneratorAlgorithm(provider, "mceliece6960119pc", PREFIX + "CMCEKeyGeneratorSpi$Mceliece6960119Pc", ISOIECObjectIdentifiers.mceliece6960119pc);
            addKeyGeneratorAlgorithm(provider, "mceliece6960119pcf", PREFIX + "CMCEKeyGeneratorSpi$Mceliece6960119Pcf", ISOIECObjectIdentifiers.mceliece6960119pcf);
            addKeyGeneratorAlgorithm(provider, "mceliece8192128", PREFIX + "CMCEKeyGeneratorSpi$Mceliece8192128", ISOIECObjectIdentifiers.mceliece8192128);
            addKeyGeneratorAlgorithm(provider, "mceliece8192128f", PREFIX + "CMCEKeyGeneratorSpi$Mceliece8192128F", ISOIECObjectIdentifiers.mceliece8192128f);
            addKeyGeneratorAlgorithm(provider, "mceliece8192128pc", PREFIX + "CMCEKeyGeneratorSpi$Mceliece8192128Pc", ISOIECObjectIdentifiers.mceliece8192128pc);
            addKeyGeneratorAlgorithm(provider, "mceliece8192128pcf", PREFIX + "CMCEKeyGeneratorSpi$Mceliece8192128Pcf", ISOIECObjectIdentifiers.mceliece8192128pcf);

            AsymmetricKeyInfoConverter keyFact = new CMCEKeyFactorySpi();

            provider.addAlgorithm("Cipher.CMCE", PREFIX + "CMCECipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher.CMCE", "CMCE");

            addCipherAlgorithm(provider, "mceliece460896", PREFIX + "CMCECipherSpi$Mceliece460896", ISOIECObjectIdentifiers.mceliece460896);
            addCipherAlgorithm(provider, "mceliece460896f", PREFIX + "CMCECipherSpi$Mceliece460896F", ISOIECObjectIdentifiers.mceliece460896f);
            addCipherAlgorithm(provider, "mceliece460896pc", PREFIX + "CMCECipherSpi$Mceliece460896Pc", ISOIECObjectIdentifiers.mceliece460896pc);
            addCipherAlgorithm(provider, "mceliece460896pcf", PREFIX + "CMCECipherSpi$Mceliece460896Pcf", ISOIECObjectIdentifiers.mceliece460896pcf);
            addCipherAlgorithm(provider, "mceliece6688128", PREFIX + "CMCECipherSpi$Mceliece6688128", ISOIECObjectIdentifiers.mceliece6688128);
            addCipherAlgorithm(provider, "mceliece6688128f", PREFIX + "CMCECipherSpi$Mceliece6688128F", ISOIECObjectIdentifiers.mceliece6688128f);
            addCipherAlgorithm(provider, "mceliece6688128pc", PREFIX + "CMCECipherSpi$Mceliece6688128Pc", ISOIECObjectIdentifiers.mceliece6688128pc);
            addCipherAlgorithm(provider, "mceliece6688128pcf", PREFIX + "CMCECipherSpi$Mceliece6688128Pcf", ISOIECObjectIdentifiers.mceliece6688128pcf);
            addCipherAlgorithm(provider, "mceliece6960119", PREFIX + "CMCECipherSpi$Mceliece6960119", ISOIECObjectIdentifiers.mceliece6960119);
            addCipherAlgorithm(provider, "mceliece6960119f", PREFIX + "CMCECipherSpi$Mceliece6960119F", ISOIECObjectIdentifiers.mceliece6960119f);
            addCipherAlgorithm(provider, "mceliece6960119pc", PREFIX + "CMCECipherSpi$Mceliece6960119Pc", ISOIECObjectIdentifiers.mceliece6960119pc);
            addCipherAlgorithm(provider, "mceliece6960119pcf", PREFIX + "CMCECipherSpi$Mceliece6960119Pcf", ISOIECObjectIdentifiers.mceliece6960119pcf);
            addCipherAlgorithm(provider, "mceliece8192128", PREFIX + "CMCECipherSpi$Mceliece8192128", ISOIECObjectIdentifiers.mceliece8192128);
            addCipherAlgorithm(provider, "mceliece8192128f", PREFIX + "CMCECipherSpi$Mceliece8192128F", ISOIECObjectIdentifiers.mceliece8192128f);
            addCipherAlgorithm(provider, "mceliece8192128pc", PREFIX + "CMCECipherSpi$Mceliece8192128Pc", ISOIECObjectIdentifiers.mceliece8192128pc);
            addCipherAlgorithm(provider, "mceliece8192128pcf", PREFIX + "CMCECipherSpi$Mceliece8192128Pcf", ISOIECObjectIdentifiers.mceliece8192128pcf);

            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece460896, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece460896f, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece460896pc, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece460896pcf, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece6688128, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece6688128f, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece6688128pc, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece6688128pcf, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece6960119, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece6960119f, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece6960119pc, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece6960119pcf, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece8192128, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece8192128f, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece8192128pc, keyFact);
            provider.addKeyInfoConverter(ISOIECObjectIdentifiers.mceliece8192128pcf, keyFact);
        }
    }
}
