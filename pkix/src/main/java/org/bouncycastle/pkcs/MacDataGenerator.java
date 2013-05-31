package org.bouncycastle.pkcs;


import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.MacCalculator;

class MacDataGenerator
{
    private PKCS12MacCalculatorBuilder builder;

    MacDataGenerator(PKCS12MacCalculatorBuilder builder)
    {
        this.builder = builder;
    }

    public MacData build(char[] password, byte[] data)
        throws PKCSException
    {
        MacCalculator     macCalculator;

        try
        {
            macCalculator = builder.build(password);

            OutputStream out = macCalculator.getOutputStream();

            out.write(data);

            out.close();
        }
        catch (Exception e)
        {
            throw new PKCSException("unable to process data: " + e.getMessage(), e);
        }

        AlgorithmIdentifier algId = macCalculator.getAlgorithmIdentifier();

        DigestInfo dInfo = new DigestInfo(builder.getDigestAlgorithmIdentifier(), macCalculator.getMac());
        PKCS12PBEParams params = PKCS12PBEParams.getInstance(algId.getParameters());

        return new MacData(dInfo, params.getIV(), params.getIterations().intValue());
    }
}
