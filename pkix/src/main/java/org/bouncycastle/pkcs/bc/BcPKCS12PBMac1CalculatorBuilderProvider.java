package org.bouncycastle.pkcs.bc;

import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilderProvider;

import java.io.IOException;

public class BcPKCS12PBMac1CalculatorBuilderProvider
    implements PKCS12MacCalculatorBuilderProvider
{
    public PKCS12MacCalculatorBuilder get(final AlgorithmIdentifier algorithmIdentifier)
    {
        return new PKCS12MacCalculatorBuilder()
        {
            public MacCalculator build(final char[] password)
                throws OperatorCreationException
            {
                if (!PKCSObjectIdentifiers.id_PBMAC1.equals(algorithmIdentifier.getAlgorithm()))
                {
                    throw new OperatorCreationException("protection algorithm not PB mac based");
                }

                BcPKCS12PBMac1CalculatorBuilder bldr;
                try
                {
                    bldr = new BcPKCS12PBMac1CalculatorBuilder(PBMAC1Params.getInstance(algorithmIdentifier.getParameters()));
                }
                catch (IOException e)
                {
                    throw new OperatorCreationException("invalid parameters in protection algorithm: " + e.getMessage());
                }
                return bldr.build(password);
            }

            public AlgorithmIdentifier getDigestAlgorithmIdentifier()
            {
                return new AlgorithmIdentifier(algorithmIdentifier.getAlgorithm(), algorithmIdentifier.getParameters());
            }
        };
    }
}
