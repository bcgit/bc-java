package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsQRUOVAes
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight QR-UOV Tests (AES PRG, categories 1 and 3)");

        // one quarter of the QRUOVTest KATs; see AllTestsQRUOV.
        suite.addTest(TestSuite.createTest(QRUOVTest.class, "testTestVectorsAes"));

        return new AllTests.BCTestSetup(suite);
    }
}
