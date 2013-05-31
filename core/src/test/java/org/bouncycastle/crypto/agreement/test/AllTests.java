package org.bouncycastle.crypto.agreement.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("JPKAE Engine Tests");

        suite.addTestSuite(JPAKEParticipantTest.class);
        suite.addTestSuite(JPAKEPrimeOrderGroupTest.class);
        suite.addTestSuite(JPAKEUtilTest.class);

        return suite;
    }
}
