package org.bouncycastle.pkix.jcajce;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

/**
 * Suite for tests that need package access to org.bouncycastle.pkix.jcajce - excluded from
 * the legacy Ant builds, where the test jar cannot share the package with the signed bcpkix jar.
 */
public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("PKIX JcaJce Tests");

        suite.addTestSuite(CrlCacheTest.class);
        suite.addTestSuite(PKIXCertPathReviewerProtocolTest.class);
        suite.addTestSuite(ReasonsMaskTest.class);
        suite.addTestSuite(RevocationUtilitiesTest.class);

        return suite;
    }
}
