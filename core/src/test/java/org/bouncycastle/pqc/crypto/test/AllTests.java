package org.bouncycastle.pqc.crypto.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.test.SimpleTestResult;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight PQ Crypto Tests");

        suite.addTestSuite(LMSTest.class);
        suite.addTestSuite(HSSTest.class);
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
        suite.addTestSuite(XMSSPublicKeyParseTest.class);
//        suite.addTestSuite(SphincsPlusTest.class);   -- now deprecated
        suite.addTestSuite(CMCEVectorTest.class);
//        suite.addTestSuite(FrodoVectorTest.class);  -- now deprecated
        suite.addTestSuite(FrodoKEMVectorTest.class);
        suite.addTestSuite(SABERVectorTest.class);
        suite.addTestSuite(NTRUTest.class);
        suite.addTestSuite(NTRUParametersTest.class);
        suite.addTestSuite(FalconTest.class);
        suite.addTestSuite(MLKEMTest.class);
        suite.addTestSuite(CrystalsDilithiumTest.class);
        suite.addTestSuite(MLDSATest.class);
        suite.addTestSuite(NTRULPRimeTest.class);
        suite.addTestSuite(SNTRUPrimeTest.class);
//        suite.addTestSuite(BIKETest.class);
        suite.addTestSuite(HQCTest.class);
        suite.addTestSuite(XWingTest.class);
        suite.addTestSuite(AllTests.SimpleTestTest.class);
        suite.addTestSuite(SLHDSATest.class);
        suite.addTestSuite(MayoTest.class);
        suite.addTestSuite(SnovaTest.class);
        suite.addTestSuite(FaestKeyPairAndSignerTest.class);
        suite.addTestSuite(FaestKatTest.class);
        suite.addTestSuite(QRUOVTest.class);
        suite.addTestSuite(HawkTest.class);
        suite.addTestSuite(UOVTest.class);
        suite.addTestSuite(MQOMTest.class);
        suite.addTestSuite(MQOMKatTest.class);
        suite.addTestSuite(SQIsignTest.class);
        suite.addTestSuite(HAETAETest.class);
        suite.addTestSuite(SDitHTest.class);
        suite.addTestSuite(PublicKeyLengthValidationTest.class);

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
