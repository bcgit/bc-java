package org.bouncycastle.gpg.test;

import java.security.Security;

import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class RegressionTest
{
    public static Test[] tests = {
        new KeyBoxTest()
    };

    public static void main(
        String[] args)
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        for (int i = 0; i != tests.length; i++)
        {
            TestResult result = tests[i].perform();
            System.out.println(result);
            if (result.getException() != null)
            {
                result.getException().printStackTrace();
            }
        }
    }
}

