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
            addSignatureAlgorithm(provider,"QTESLA-II", PREFIX + "SignatureSpi$HeuristicII", PQCObjectIdentifiers.qTESLA_II);
            addSignatureAlgorithm(provider,"QTESLA-III", PREFIX + "SignatureSpi$HeuristicIII", PQCObjectIdentifiers.qTESLA_III);
            addSignatureAlgorithm(provider,"QTESLA-V", PREFIX + "SignatureSpi$HeuristicV", PQCObjectIdentifiers.qTESLA_V);
            addSignatureAlgorithm(provider,"QTESLA-V-SIZE", PREFIX + "SignatureSpi$HeuristicV_SIZE", PQCObjectIdentifiers.qTESLA_V_SIZE);
            addSignatureAlgorithm(provider,"QTESLA-P-I", PREFIX + "SignatureSpi$PI", PQCObjectIdentifiers.qTESLA_p_I);
            addSignatureAlgorithm(provider,"QTESLA-P-III", PREFIX + "SignatureSpi$PIII", PQCObjectIdentifiers.qTESLA_p_III);

            AsymmetricKeyInfoConverter keyFact = new QTESLAKeyFactorySpi();

            registerOid(provider, PQCObjectIdentifiers.qTESLA_I, "QTESLA-I", keyFact);
            registerOid(provider, PQCObjectIdentifiers.qTESLA_II, "QTESLA-II", keyFact);
            registerOid(provider, PQCObjectIdentifiers.qTESLA_III, "QTESLA-III", keyFact);
            registerOid(provider, PQCObjectIdentifiers.qTESLA_V, "QTESLA-V", keyFact);
            registerOid(provider, PQCObjectIdentifiers.qTESLA_V_SIZE, "QTESLA-V-SIZE", keyFact);
            registerOid(provider, PQCObjectIdentifiers.qTESLA_p_I, "QTESLA-P-I", keyFact);
            registerOid(provider, PQCObjectIdentifiers.qTESLA_p_III, "QTESLA-P-III", keyFact);
        }
    }
}
