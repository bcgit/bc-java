package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsSQIsignLvl5
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight SQIsign Tests (level 5)");

        // see AllTestsSQIsign.
        suite.addTest(TestSuite.createTest(SQIsignTest.class, "testTestVectorsLvl5"));

        return new AllTests.BCTestSetup(suite);
    }
}
