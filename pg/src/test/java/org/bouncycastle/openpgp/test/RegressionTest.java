package org.bouncycastle.openpgp.test;

import java.security.Security;

import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class RegressionTest
{
    public static Test[]    tests = {
        new BcPGPKeyRingTest(),
        new PGPKeyRingTest(),
        new BcPGPRSATest(),
        new PGPRSATest(),
        new BcPGPDSATest(),
        new PGPDSATest(),
        new BcPGPDSAElGamalTest(),
        new PGPDSAElGamalTest(),
        new BcPGPPBETest(),
        new PGPPBETest(),
        new PGPMarkerTest(),
        new PGPPacketTest(),
        new PGPArmoredTest(),
        new PGPSignatureTest(),
        new PGPClearSignedSignatureTest(),
        new PGPCompressionTest(),
        new PGPNoPrivateKeyTest(),
        new PGPECDSATest(),
        new PGPECDHTest(),
        new PGPParsingTest()
    };

    public static void main(
        String[]    args)
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        for (int i = 0; i != tests.length; i++)
        {
            TestResult  result = tests[i].perform();
            System.out.println(result);
            if (result.getException() != null)
            {
                result.getException().printStackTrace();
            }
        }
    }
}

