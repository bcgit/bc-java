package org.bouncycastle.crypto.hash2curve.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.crypto.hash2curve.test.impl.GenericSqrtRatioCalculatorTest;
import org.bouncycastle.crypto.hash2curve.test.impl.SimplifiedShallueVanDeWoestijneMapToCurveTest;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
       PrintTestResult.printResult( junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Hash2Curve Tests");

        suite.addTestSuite(HashToFieldTest.class);
        suite.addTestSuite(OPRFHashToScalarTest.class);
        suite.addTestSuite(GenericSqrtRatioCalculatorTest.class);

        suite.addTestSuite(SimplifiedShallueVanDeWoestijneMapToCurveTest.class);
        suite.addTestSuite(H2cUtilsTest.class);
        suite.addTestSuite(HashToEllipticCurveTest.class);
        suite.addTestSuite(BLS12_381G1HashToCurveTest.class);
        suite.addTestSuite(BLS12_381G2HashToCurveTest.class);
        suite.addTestSuite(Fp6Fp12Test.class);
        suite.addTestSuite(BLS12_381PairingTest.class);
        suite.addTestSuite(BLS12_381BasicSchemeTest.class);
        suite.addTestSuite(BLS12_381SuitesTest.class);
        suite.addTestSuite(BLS12_381SerializationTest.class);
        suite.addTestSuite(BLS12_381SubgroupCheckTest.class);
        suite.addTestSuite(BLS12_381Eth2KatTest.class);
        suite.addTestSuite(BLS12_381ConstantTimeMulTest.class);
        suite.addTestSuite(BLSKeyPairGeneratorTest.class);
        suite.addTestSuite(BLSSignerTest.class);

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
