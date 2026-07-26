package org.bouncycastle.mail.smime.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// NOTE: jdk1.3 overlay. NewSMIMESignedTest is excluded from the jdk1.3 build (post-1.3 JDK APIs,
// ant/jdk13.xml) so its reference is dropped here.
public class AllTests
{
    public static void main (String[] args)
        throws Exception
    {
       PrintTestResult.printResult( junit.textui.TestRunner.run (suite()));
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite= new TestSuite("SMIME tests");

        suite.addTestSuite(NewSMIMEEnvelopedTest.class);
        suite.addTestSuite(SMIMECompressedTest.class);
        suite.addTestSuite(SMIMEMiscTest.class);
        suite.addTestSuite(SMIMEToolkitTest.class);

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
