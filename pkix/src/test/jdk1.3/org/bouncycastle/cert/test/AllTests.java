package org.bouncycastle.cert.test;

import java.security.Security;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;

public class AllTests
    extends TestCase
{
    public void testSimpleTests()
    {
        org.bouncycastle.util.test.Test[] tests = new org.bouncycastle.util.test.Test[] { new CertTest(), new PKCS10Test(), new AttrCertSelectorTest(), new AttrCertTest(), new X509ExtensionUtilsTest() };

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
        junit.textui.TestRunner.run(suite());
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
        suite.addTestSuite(BcPKCS10Test.class);
        suite.addTest(ConverterTest.suite());

        return suite;
    }
}
