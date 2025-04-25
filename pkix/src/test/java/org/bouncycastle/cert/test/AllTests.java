package org.bouncycastle.cert.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.test.SimpleTestResult;

public class AllTests
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    
    public void testSimpleTests()
    {
        org.bouncycastle.util.test.Test[] tests = new org.bouncycastle.util.test.Test[]
        {
            new AttrCertSelectorTest(),
            new AttrCertTest(),
            new CertPathLoopTest(),
            new CertTest(),
            new DANETest(),
            new ExternalKeyTest(),
            new GOST3410_2012CMSTest(),
            new GOSTR3410_2012_256GenerateCertificate(),
            new MLDSACredentialsTest(),
            new PKCS10Test(),
            new SLHDSACredentialsTest(),
            new X509ExtensionUtilsTest(),
        };

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult  result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                if (result.getException() != null)
                {
                    result.getException().printStackTrace();
                }
                fail(result.toString());
            }
        }
    }

    public static void main (String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Cert Tests");

        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        suite.addTestSuite(AllTests.class);
        suite.addTestSuite(BcAttrCertSelectorTest.class);
        suite.addTestSuite(BcAttrCertSelectorTest.class);
        suite.addTestSuite(BcAttrCertTest.class);
        suite.addTestSuite(BcCertTest.class);
        suite.addTestSuite(BcPKCS10Test.class);
        suite.addTestSuite(PQCPKCS10Test.class);
        suite.addTest(ConverterTest.suite());

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