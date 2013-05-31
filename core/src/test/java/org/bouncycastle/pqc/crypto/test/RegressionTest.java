package org.bouncycastle.pqc.crypto.test;

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

