package org.bouncycastle.crypto.agreement.owl.test;

// NOTE: overlay of the base AllTests without OwlUtilTest. OwlUtilTest sits directly in
// org.bouncycastle.crypto.agreement.owl to reach the package-private OwlUtil, so it is excluded
// from the signed provider jar and lands in bctest instead. On a real JRE all classes of one
// package must share signer info, so loading it from the unsigned/separately-signed test jar
// alongside the signed provider's owl classes fails with
// "signer information does not match signer information of other classes in the same package".
// The Gradle build runs OwlUtilTest from the base AllTests, where both live in one source set.

import junit.extensions.TestSetup;
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
        TestSuite suite = new TestSuite("Owl Engine Tests");

        suite.addTestSuite(OwlCurveTest.class);
        suite.addTestSuite(OwlClientRegistrationTest.class);
        suite.addTestSuite(OwlServerRegistrationTest.class);
        suite.addTestSuite(OwlClientTest.class);
        suite.addTestSuite(OwlServerTest.class);

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
        }

        protected void tearDown()
        {
        }
    }
}
