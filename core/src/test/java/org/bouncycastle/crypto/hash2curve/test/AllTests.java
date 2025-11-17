package org.bouncycastle.crypto.hash2curve.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.crypto.hash2curve.test.impl.GenericSqrtRatioCalculatorTest;
import org.bouncycastle.crypto.hash2curve.test.impl.ShallueVanDeWoestijneMapToCurveTest;
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

        suite.addTestSuite(ShallueVanDeWoestijneMapToCurveTest.class);
        suite.addTestSuite(H2cUtilsTest.class);
        suite.addTestSuite(HashToEllipticCurveTest.class);

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
