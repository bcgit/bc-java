package org.bouncycastle.jcacje.provider.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;


public class AllTests21
    extends TestCase
{
    public static void main(String[] args)
    {

        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("JDK21 Provider Tests");
        suite.addTestSuite(NTRUKEMTest.class);
        suite.addTestSuite(SNTRUPrimeKEMTest.class);
        return suite;
    }
}
