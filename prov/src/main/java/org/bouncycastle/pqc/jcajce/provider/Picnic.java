package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.picnic.PicnicKeyFactorySpi;

public class Picnic
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".picnic.";

    public static class Mappings
            extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.PICNIC", PREFIX + "PicnicKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.PICNIC", PREFIX + "PicnicKeyPairGeneratorSpi");

            addSignatureAlgorithm(provider, "PICNIC", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.picnic_signature);

            addSignatureAlgorithm(provider, "SHAKE256","PICNIC", PREFIX + "SignatureSpi$withShake256", BCObjectIdentifiers.picnic_with_shake256);
            addSignatureAlgorithm(provider, "SHA512","PICNIC", PREFIX + "SignatureSpi$withSha512", BCObjectIdentifiers.picnic_with_sha512);
            addSignatureAlgorithm(provider, "SHA3-512","PICNIC", PREFIX + "SignatureSpi$withSha3512", BCObjectIdentifiers.picnic_with_sha3_512);

            AsymmetricKeyInfoConverter keyFact = new PicnicKeyFactorySpi();

            registerOid(provider, BCObjectIdentifiers.picnic_key, "Picnic", keyFact);
            registerOid(provider, BCObjectIdentifiers.picnicl1fs, "Picnic", keyFact);
            registerOid(provider, BCObjectIdentifiers.picnicl1ur, "Picnic", keyFact);
            registerOid(provider, BCObjectIdentifiers.picnicl3fs, "Picnic", keyFact);
            registerOid(provider, BCObjectIdentifiers.picnicl3ur, "Picnic", keyFact);
            registerOid(provider, BCObjectIdentifiers.picnicl5fs, "Picnic", keyFact);
            registerOid(provider, BCObjectIdentifiers.picnicl5ur, "Picnic", keyFact);
            registerOid(provider, BCObjectIdentifiers.picnic3l1, "Picnic", keyFact);
            registerOid(provider, BCObjectIdentifiers.picnic3l3, "Picnic", keyFact);
            registerOid(provider, BCObjectIdentifiers.picnic3l5, "Picnic", keyFact);
            registerOid(provider, BCObjectIdentifiers.picnicl1full, "Picnic", keyFact);
            registerOid(provider, BCObjectIdentifiers.picnicl3full, "Picnic", keyFact);
            registerOid(provider, BCObjectIdentifiers.picnicl5full, "Picnic", keyFact);
        }
    }
}
