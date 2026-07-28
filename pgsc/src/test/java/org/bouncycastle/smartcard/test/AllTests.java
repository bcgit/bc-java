package org.bouncycastle.smartcard.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.smartcard.simulator.SimulatorTests;
import org.bouncycastle.smartcard.yubikey.YubikeyTests;
import org.bouncycastle.test.PrintTestResult;

import java.security.Security;

public class AllTests
        extends TestCase
{

    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("OpenPGP SmartCard Tests");

        suite.addTestSuite(SimulatorTests.class);
        suite.addTestSuite(YubikeyTests.class);

        return new BCTestSetup(suite);
    }

    static class BCTestSetup
            extends TestSetup
    {
        public BCTestSetup(Test test)
        {
            super(test);
        }

        protected void setUp()
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        protected void tearDown()
        {
            Security.removeProvider("BC");
        }
    }
}
