package org.bouncycastle.pqc.crypto.faest;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.test.SimpleTestResult;

/**
 * Aggregates the internal FAEST {@code SimpleTest} suites into a JUnit3 runner.
 * Each {@code testXxx} method wraps one {@code SimpleTest.perform()} call and
 * fails the JUnit case if the underlying SimpleTest reports failure.
 */
public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight FAEST PQ Crypto Tests");

        suite.addTestSuite(AllTests.class);

        return new BCTestSetup(suite);
    }

    public void testFaestField()              { run(new FaestFieldTest()); }
    public void testFaestExtendedField()      { run(new FaestExtendedFieldTest()); }
    public void testFaestFieldHelpers()       { run(new FaestFieldHelpersTest()); }
    public void testRandomOracle()            { run(new RandomOracleTest()); }
    public void testUniversalHashing()        { run(new UniversalHashingTest()); }
    public void testBAVC()                    { run(new BAVCTest()); }
    public void testVOLE()                    { run(new VOLETest()); }
    public void testFaestAES()                { run(new FaestAESTest()); }
    public void testAesWitnessExtension()     { run(new AesWitnessExtensionTest()); }
    public void testFaestProofPrimitives()    { run(new FaestProofPrimitivesTest()); }
    public void testFaestProofPrimitivesAffine() { run(new FaestProofPrimitivesAffineTest()); }
    public void testFaestKeyExpansion()       { run(new FaestKeyExpansionTest()); }
    public void testFaestAESConstraints()     { run(new FaestAESConstraintsTest()); }
    public void testFaestProof()              { run(new FaestProofTest()); }
    public void testFaestSignVerify()         { run(new FaestSignVerifyTest()); }

    private static void run(org.bouncycastle.util.test.SimpleTest t)
    {
        SimpleTestResult r = (SimpleTestResult)t.perform();
        if (!r.isSuccessful())
        {
            if (r.getException() != null)
            {
                r.getException().printStackTrace();
            }
            fail(r.toString());
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
