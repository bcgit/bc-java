package org.bouncycastle.jce.provider;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.test.PrintTestResult;

/**
 * Full test suite for the BCPQC provider.
 */
public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("PQC JCE Tests");
        
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        suite.addTestSuite(CrlCacheTest.class);
        suite.addTestSuite(MultiValuedRDNEmailTest.class);

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
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        protected void tearDown()
        {
            Security.removeProvider("BCPQC");
        }
    }
}
