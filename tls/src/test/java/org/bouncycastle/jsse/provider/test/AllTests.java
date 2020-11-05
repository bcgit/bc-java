package org.bouncycastle.jsse.provider.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("JSSE tests");

        suite.addTestSuite(BasicClientAuthTlsTest.class);
        suite.addTestSuite(BasicTlsTest.class);
        suite.addTestSuite(ConfigTest.class);
        suite.addTestSuite(EdDSACredentialsTest.class);
        suite.addTestSuite(InstanceTest.class);
        suite.addTestSuite(KeyManagerFactoryTest.class);
        suite.addTestSuite(PSSCredentialsTest.class);
        suite.addTestSuite(SSLServerSocketTest.class);
        suite.addTestSuite(SSLSocketTest.class);

        if (hasClass("javax.net.ssl.CertPathTrustManagerParameters"))
        {
            suite.addTestSuite(TrustManagerFactoryTest.class);
        }

        suite.addTest(CipherSuitesTestSuite.suite());
        suite.addTest(CipherSuitesEngineTestSuite.suite());
        suite.addTest(FipsCipherSuitesTestSuite.suite());
        suite.addTest(FipsCipherSuitesEngineTestSuite.suite());

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

    private static boolean hasClass(String name)
    {
        try
        {
            AllTests.class.getClassLoader().loadClass(name);
            return true;
        }
        catch (Exception e)
        {
            return false;
        }
    }
}
