package org.bouncycastle.tls.crypto.test;

import org.bouncycastle.test.PrintTestResult;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

// NOTE: jdk1.4 overlay - omits JcaTlsRSAPSSAltProviderTest (excluded in ant/jdk14.xml): the jdk1.4
// JcaTlsCrypto overlay deliberately drops the PKCS#11/SunMSCAPI PSS signature-name fallbacks.
public class AllTests
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("TLS crypto tests");

        suite.addTestSuite(BcTlsCryptoTest.class);
        suite.addTestSuite(JcaTlsCryptoTest.class);

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

        }

        protected void tearDown()
        {

        }
    }
}
