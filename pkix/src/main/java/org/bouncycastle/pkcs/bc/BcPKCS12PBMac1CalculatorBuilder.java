package org.bouncycastle.pkcs.bc;

import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;

import java.io.IOException;

public class BcPKCS12PBMac1CalculatorBuilder
    implements PKCS12MacCalculatorBuilder
{    
    private final PBMAC1Params pbmac1Params;
    private PBKDF2Params pbkdf2Params = null;

    public BcPKCS12PBMac1CalculatorBuilder(PBMAC1Params pbeMacParams) throws IOException
    {
        this.pbmac1Params = pbeMacParams;
        if (PKCSObjectIdentifiers.id_PBKDF2.equals(pbeMacParams.getKeyDerivationFunc().getAlgorithm()))
        {
            this.pbkdf2Params = PBKDF2Params.getInstance(pbeMacParams.getKeyDerivationFunc().getParameters());
            if (pbkdf2Params.getKeyLength() == null)
            {
                throw new IOException("Key length must be present when using PBMAC1.");
            }
        }
        // TODO handle other cases
    }

    @Override
    public AlgorithmIdentifier getDigestAlgorithmIdentifier()
    {
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1, pbmac1Params);
    }

    public MacCalculator build(final char[] password) throws OperatorCreationException
    {
        return PKCS12PBEUtils.createPBMac1Calculator(pbmac1Params, pbkdf2Params, password);
    }
}
