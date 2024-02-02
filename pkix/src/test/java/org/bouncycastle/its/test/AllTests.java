package org.bouncycastle.its.test;

import java.security.Security;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("ITS tests");

        suite.addTestSuite(ITSBasicTest.class);
        suite.addTestSuite(ITSCertLoadTest.class);
        suite.addTestSuite(ITSJcaJceBasicTest.class);
        suite.addTestSuite(ETSIDataSignerTest.class);
        suite.addTestSuite(ETSIEncryptedDataTest.class);

        return new ITSTestSetup(suite);
    }

    public void setUp()
    {
        if (Security.getProvider(BC) != null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
