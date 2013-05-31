package org.bouncycastle.jce.provider.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class RegressionTest
{
    public static Test[]    tests = {
        new FIPSDESTest(),
        new BlockCipherTest(),
        new MacTest(),
        new SealedTest(),
        new RSATest(),
        new SigTest(),
        new CertTest(),
        new KeyStoreTest(),
        new DigestTest(),
        new WrapTest(),
        new CertPathTest(),
        new CertStoreTest(),
        new CertPathValidatorTest(),
        new CertPathBuilderTest()
    };

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        for (int i = 0; i != tests.length; i++)
        {
            TestResult  result = tests[i].perform();
            
            if (((SimpleTestResult)result).getException() != null)
            {
                ((SimpleTestResult)result).getException().printStackTrace();
            }
            System.out.println(result);
        }
    }
}

