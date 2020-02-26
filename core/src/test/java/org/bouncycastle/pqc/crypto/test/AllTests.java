package org.bouncycastle.pqc.crypto.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.util.test.SimpleTestResult;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight PQ Crypto Tests");

        suite.addTestSuite(BitStringTest.class);
        suite.addTestSuite(EncryptionKeyTest.class);
        suite.addTestSuite(NTRUEncryptionParametersTest.class);
        suite.addTestSuite(NTRUEncryptTest.class);
        suite.addTestSuite(NTRUSignatureParametersTest.class);
        suite.addTestSuite(NTRUSignatureKeyTest.class);
        suite.addTestSuite(NTRUSignerTest.class);
        suite.addTestSuite(NTRUSigningParametersTest.class);
        suite.addTestSuite(QTESLATest.class);
        suite.addTestSuite(XMSSMTPrivateKeyTest.class);
        suite.addTestSuite(XMSSMTPublicKeyTest.class);
        suite.addTestSuite(XMSSMTSignatureTest.class);
        suite.addTestSuite(XMSSMTTest.class);
        suite.addTestSuite(XMSSOidTest.class);
        suite.addTestSuite(XMSSPrivateKeyTest.class);
        suite.addTestSuite(XMSSPublicKeyTest.class);
        suite.addTestSuite(XMSSReducedSignatureTest.class);
        suite.addTestSuite(XMSSSignatureTest.class);
        suite.addTestSuite(XMSSTest.class);
        suite.addTestSuite(XMSSUtilTest.class);
        suite.addTestSuite(AllTests.SimpleTestTest.class);

        return new BCTestSetup(suite);
    }

    public static class SimpleTestTest
        extends TestCase
    {
        public void testPQC()
        {
            org.bouncycastle.util.test.Test[] tests = RegressionTest.tests;

            for (int i = 0; i != tests.length; i++)
            {
                SimpleTestResult result = (SimpleTestResult)tests[i].perform();

                if (!result.isSuccessful())
                {
                    if (result.getException() != null)
                    {
                        result.getException().printStackTrace();
                    }
                    fail(result.toString());
                }
            }
        }
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
