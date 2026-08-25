package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsQRUOV
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight QR-UOV Tests (SHAKE PRG, categories 1 and 3)");

        // the other QRUOVTest KAT methods run from AllTestsQRUOVCat5 / AllTestsQRUOVAes /
        // AllTestsQRUOVAesCat5 so the four halves, each minutes of KATs, run as separate (parallel) forks.
        suite.addTest(TestSuite.createTest(QRUOVTest.class, "testTestVectorsShake"));

        return new AllTests.BCTestSetup(suite);
    }
}
