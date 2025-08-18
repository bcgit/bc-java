package org.bouncycastle.mail.smime.test;

import java.security.Security;
import java.util.Enumeration;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestResult;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        TestResult tr = junit.textui.TestRunner.run(suite());

        Enumeration e = tr.failures();
        if (e != null)
        {
            while (e.hasMoreElements())
            {
                System.out.println(e.nextElement());
            }
        }

        e = tr.failures();
        if (e != null)
        {
            while (e.hasMoreElements())
            {
                System.out.println(e.nextElement());
            }
        }

        if (!tr.wasSuccessful())
        {
            System.exit(1);
        }
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("SMIME tests");

        suite.addTestSuite(JournalingSecureRandomEncryptTest.class);
        suite.addTestSuite(MailGeneralTest.class);
        suite.addTestSuite(NewSMIMEAuthEnvelopedTest.class);
        suite.addTestSuite(NewSMIMEEnvelopedTest.class);
        suite.addTestSuite(NewSMIMESignedTest.class);
        suite.addTestSuite(SignedMailValidatorTest.class);
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
