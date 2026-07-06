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
        // XMSS tests split out into AllTestsXMSS so they can run as a separate (parallel) fork.
//        suite.addTestSuite(SphincsPlusTest.class);   -- now deprecated
        // CMCE (Classic McEliece) tests split out into AllTestsCMCE so they can run as a separate (parallel) fork.
//        suite.addTestSuite(FrodoVectorTest.class);  -- now deprecated
        suite.addTestSuite(FrodoVectorTest.class);
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
        // SLHDSA tests split out into AllTestsSLHDSA so they can run as a separate (parallel) fork.
        suite.addTestSuite(MayoTest.class);
        // MayoRetryTest lives in the package-private org.bouncycastle.pqc.crypto.mayo package
        // (it overrides MayoSigner.sampleSolution) and is run from that package's own AllTests,
        // so the signed-jar legacy Ant builds can drop it without breaking this shared suite.
        // SNOVA tests split out into AllTestsSnova so they can run as a separate (parallel) fork.
        // FAEST tests split out into AllTestsFaest so they can run as a separate (parallel) fork.
        // QRUOV tests split out into AllTestsQRUOV so they can run as a separate (parallel) fork.
        // Hawk tests split out into AllTestsHawk so they can run as a separate (parallel) fork.
        suite.addTestSuite(UOVTest.class);
        // MQOM tests split out into AllTestsMQOM so they can run as a separate (parallel) fork.
        suite.addTestSuite(SQIsignTest.class);
        suite.addTestSuite(HAETAETest.class);
        suite.addTestSuite(SDitHTest.class);
        suite.addTestSuite(AIMerTest.class);
        suite.addTestSuite(PublicKeyLengthValidationTest.class);
        suite.addTestSuite(PqcMalformedInputTest.class);

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
