package org.bouncycastle.gpg.test;

import java.security.Security;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[] tests = {
        new KeyBoxTest()
    };

    public static void main(String[] args)
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        SimpleTest.runTests(tests);
    }
}
