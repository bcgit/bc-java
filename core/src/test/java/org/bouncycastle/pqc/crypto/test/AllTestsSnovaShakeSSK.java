package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsSnovaShakeSSK
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight SNOVA Tests (SHAKE, SSK)");

        // one quarter of the SnovaTest KATs; see AllTestsSnova.
        suite.addTest(TestSuite.createTest(SnovaTest.class, "testTestVectorsShakeSSK"));

        return new AllTests.BCTestSetup(suite);
    }
}
