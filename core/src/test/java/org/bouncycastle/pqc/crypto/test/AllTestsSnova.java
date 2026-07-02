package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsSnova
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight SNOVA Tests");

        suite.addTestSuite(SnovaTest.class);

        return new AllTests.BCTestSetup(suite);
    }
}
