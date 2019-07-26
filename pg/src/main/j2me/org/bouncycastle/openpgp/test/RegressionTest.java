package org.bouncycastle.openpgp.test;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new BcPGPDSAElGamalTest(),
        new BcPGPDSATest(),
        new BcPGPKeyRingTest(),
        new BcPGPPBETest(),
        new BcPGPRSATest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
