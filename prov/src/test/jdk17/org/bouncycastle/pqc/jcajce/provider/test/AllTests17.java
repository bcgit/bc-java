package org.bouncycastle.pqc.jcajce.provider.test;

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
        TestSuite suite = new TestSuite("PQC JCE Tests (JDK 17)");
        suite.addTestSuite(CMCEKEM17Test.class);
        suite.addTestSuite(FrodoKEM17Test.class);
        suite.addTestSuite(HQCKEM17Test.class);
        suite.addTestSuite(MLKEM17Test.class);
        suite.addTestSuite(NTRUKEM17Test.class);
        suite.addTestSuite(NTRULPRimeKEM17Test.class);
        suite.addTestSuite(NTRUPlusKEM17Test.class);
        suite.addTestSuite(SmaugTKEM17Test.class);
        suite.addTestSuite(SNTRUPrimeKEM17Test.class);
        suite.addTestSuite(org.bouncycastle.jce.provider.test.SM9KEM17Test.class);
        return suite;
    }
}
