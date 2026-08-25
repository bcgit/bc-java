package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsMQOMCat3
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight MQOM Tests (category 3)");

        // one third of the MQOMKatTest KATs; see AllTestsMQOM.
        suite.addTest(TestSuite.createTest(MQOMKatTest.class, "testCat3Variants"));

        return new AllTests.BCTestSetup(suite);
    }
}
