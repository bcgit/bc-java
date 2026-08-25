package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsSQIsign
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight SQIsign Tests (levels 1 and 3)");

        // the level 5 KATs run from AllTestsSQIsignLvl5 so the two halves run as separate (parallel) forks.
        suite.addTest(TestSuite.createTest(SQIsignTest.class, "testTestVectorsLvl1"));
        suite.addTest(TestSuite.createTest(SQIsignTest.class, "testTestVectorsLvl3"));

        return new AllTests.BCTestSetup(suite);
    }
}
