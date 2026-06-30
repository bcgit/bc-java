package org.bouncycastle.jsse.provider;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Suite for tests that need package-private access to {@code org.bouncycastle.jsse.provider}
 * internals (e.g. {@link HostnameUtil}). Aggregated by
 * {@code org.bouncycastle.jsse.provider.test.AllTests}.
 */
public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("JSSE provider internal tests");

        suite.addTestSuite(HostnameUtilTest.class);

        return suite;
    }
}
