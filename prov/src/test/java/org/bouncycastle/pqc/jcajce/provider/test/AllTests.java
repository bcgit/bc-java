package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("PQC JCE Tests");
        
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        
        suite.addTestSuite(RainbowSignatureTest.class);
        suite.addTestSuite(McElieceFujisakiCipherTest.class);
        suite.addTestSuite(McElieceKobaraImaiCipherTest.class);
        suite.addTestSuite(McEliecePointchevalCipherTest.class);
        suite.addTestSuite(McEliecePKCSCipherTest.class);

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
