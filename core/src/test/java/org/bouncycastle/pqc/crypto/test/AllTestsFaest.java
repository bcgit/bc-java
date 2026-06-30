package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsFaest
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight FAEST Tests");

        suite.addTestSuite(FaestKeyPairAndSignerTest.class);
        suite.addTestSuite(FaestKatTest.class);

        return new AllTests.BCTestSetup(suite);
    }
}
