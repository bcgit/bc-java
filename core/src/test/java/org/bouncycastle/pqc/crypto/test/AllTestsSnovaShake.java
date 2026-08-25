package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsSnovaShake
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight SNOVA Tests (SHAKE, ESK)");

        // one quarter of the SnovaTest KATs; see AllTestsSnova.
        suite.addTest(TestSuite.createTest(SnovaTest.class, "testTestVectorsShakeESK"));

        return new AllTests.BCTestSetup(suite);
    }
}
