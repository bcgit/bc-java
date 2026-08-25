package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsMQOM
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight MQOM Tests");

        suite.addTestSuite(MQOMTest.class);
        // the category 3 and 5 MQOMKatTest KATs run from AllTestsMQOMCat3 / AllTestsMQOMCat5
        // so the three categories, each minutes of signing, run as separate (parallel) forks.
        suite.addTest(TestSuite.createTest(MQOMKatTest.class, "testCat1Variants"));

        return new AllTests.BCTestSetup(suite);
    }
}
