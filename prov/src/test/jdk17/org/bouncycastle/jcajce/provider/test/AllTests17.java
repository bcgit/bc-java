package org.bouncycastle.jcajce.provider.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;


public class AllTests17
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("JDK17 Provider Tests");
        suite.addTestSuite(NTRUKEMTest.class);
        suite.addTestSuite(SNTRUPrimeKEMTest.class);
        suite.addTestSuite(MLKEMTest.class);
        suite.addTestSuite(HQCTest.class);
        return suite;
    }
}
