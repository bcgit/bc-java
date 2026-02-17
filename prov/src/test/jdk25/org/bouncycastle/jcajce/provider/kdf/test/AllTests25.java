package org.bouncycastle.jcajce.provider.kdf.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTests25
        extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("JDK25 Provider Tests");
        suite.addTestSuite(HKDFTest.class);
        suite.addTestSuite(PBEPBKDF2Test.class);
        suite.addTestSuite(ScryptTest.class);
        return suite;
    }
}

