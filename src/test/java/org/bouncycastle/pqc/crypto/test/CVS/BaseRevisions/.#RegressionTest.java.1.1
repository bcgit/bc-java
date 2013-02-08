package org.bouncycastle.pqc.crypto.test;

import java.security.Security;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class RegressionTest
{
    public static Test[]    tests = {
        new GMSSSignerTest(),
        new McElieceFujisakiCipherTest(),
        new McElieceKobaraImaiCipherTest(),
        new McEliecePKCSCipherTest(),
        new McEliecePointchevalCipherTest(),
        new RainbowSignerTest()
    };

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastlePQCProvider());

        System.out.println("Testing " + Security.getProvider("BCPQC").getInfo() + " version: " + Security.getProvider("BCPQC").getVersion());
        
        for (int i = 0; i != tests.length; i++)
        {
            TestResult  result = tests[i].perform();
            
            if (result.getException() != null)
            {
                result.getException().printStackTrace();
            }
            
            System.out.println(result);
        }
    }
}

