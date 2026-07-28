package org.bouncycastle.pkix.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    // NOTE: jdk1.3 overlay. RevocationTest, CheckNameConstraintsTest, IDPRelativeNameTest,
    // QcStatementReviewerTest, PKIXCertPathReviewerPolicyTreeTest and
    // PKIXCertPathReviewerCrlReasonTest are all excluded from the jdk1.3 build (post-1.3 JDK
    // APIs, ant/jdk13.xml), leaving only CheckerTest.
    public static Test suite()
    {
        TestSuite suite = new TestSuite("PKIX Tests");

        suite.addTestSuite(CheckerTest.class);

        return new BCTestSetup(suite);
    }

    static class BCTestSetup
        extends TestSetup
    {
        public BCTestSetup(Test test)
        {
            super(test);
        }

        protected void setUp()
        {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }

        protected void tearDown()
        {
            Security.removeProvider("BC");
        }
    }
}
