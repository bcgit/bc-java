package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.provider.qtesla.QTESLAKeyFactorySpi;

public class QTESLA
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".qtesla.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.QTESLA", PREFIX + "QTESLAKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.QTESLA", PREFIX + "KeyPairGeneratorSpi");

            provider.addAlgorithm("Signature.QTESLA", PREFIX + "SignatureSpi$qTESLA");

            addSignatureAlgorithm(provider,"QTESLA-I", PREFIX + "SignatureSpi$HeuristicI", PQCObjectIdentifiers.qTESLA_I);
            addSignatureAlgorithm(provider,"QTESLA-III-SIZE", PREFIX + "SignatureSpi$HeuristicIIISize", PQCObjectIdentifiers.qTESLA_III_size);
            addSignatureAlgorithm(provider,"QTESLA-III-SPEED", PREFIX + "SignatureSpi$HeuristicIIISpeed", PQCObjectIdentifiers.qTESLA_III_speed);
            addSignatureAlgorithm(provider,"QTESLA-P-I", PREFIX + "SignatureSpi$ProvablySecureI", PQCObjectIdentifiers.qTESLA_p_I);
            addSignatureAlgorithm(provider,"QTESLA-P-III", PREFIX + "SignatureSpi$ProvablySecureIII", PQCObjectIdentifiers.qTESLA_p_III);

            AsymmetricKeyInfoConverter keyFact = new QTESLAKeyFactorySpi();

            registerOid(provider, PQCObjectIdentifiers.qTESLA_I, "QTESLA-I", keyFact);
            registerOid(provider, PQCObjectIdentifiers.qTESLA_III_size, "QTESLA-III-SIZE", keyFact);
            registerOid(provider, PQCObjectIdentifiers.qTESLA_III_speed, "QTESLA-III-SPEED", keyFact);
            registerOid(provider, PQCObjectIdentifiers.qTESLA_p_I, "QTESLA-P-I", keyFact);
            registerOid(provider, PQCObjectIdentifiers.qTESLA_p_III, "QTESLA-P-III", keyFact);
        }
    }
}
