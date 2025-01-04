package org.bouncycastle.pkcs;



import java.io.OutputStream;

import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.util.Strings;

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
        byte[] salt;
        int iterations;
        
        if (PKCSObjectIdentifiers.id_PBMAC1.equals(dInfo.getAlgorithmId().getAlgorithm())) 
        {
            salt = Strings.toUTF8ByteArray("NOT USED".toCharArray());
            iterations = 1;
        }
        else
        {
            PKCS12PBEParams params = PKCS12PBEParams.getInstance(algId.getParameters());
            salt = params.getIV();
            iterations = params.getIterations().intValue();
        }
        
        return new MacData(dInfo, salt, iterations);
    }
}
