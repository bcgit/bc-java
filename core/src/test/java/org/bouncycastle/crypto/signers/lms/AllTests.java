package org.bouncycastle.crypto.signers.lms;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("LMS engine tests");

        suite.addTestSuite(LMOtsTests.class);
        suite.addTestSuite(TypeTests.class);

        return suite;
    }
}
