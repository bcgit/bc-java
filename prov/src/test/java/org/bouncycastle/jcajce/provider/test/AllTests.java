package org.bouncycastle.jcajce.provider.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("JCAJCE Provider Tests");

        suite.addTestSuite(ECAlgorithmParametersTest.class);
        suite.addTestSuite(GeneralKeyTest.class);
        suite.addTestSuite(HybridRandomProviderTest.class);
        suite.addTestSuite(PrivateConstructorTest.class);
        suite.addTestSuite(RandomTest.class);
        suite.addTestSuite(RFC3211WrapTest.class);
        suite.addTestSuite(BouncyCastleProviderTest.class);

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
            Security.addProvider(new BouncyCastleProvider());
        }

        protected void tearDown()
        {
            Security.removeProvider("BC");
        }
    }
}
