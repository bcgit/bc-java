package org.bouncycastle.mail.smime.test;

import junit.framework.Test;
import junit.framework.TestSuite;

public class AllTests
{
    public static void main (String[] args)
        throws Exception
    {
        junit.textui.TestRunner.run (suite());
    }
    
    public static Test suite()
        throws Exception
    {
        TestSuite suite= new TestSuite("SMIME tests");

        suite.addTest(NewSMIMESignedTest.suite());
        suite.addTest(SignedMailValidatorTest.suite());
        suite.addTest(NewSMIMEEnvelopedTest.suite());
        suite.addTest(SMIMECompressedTest.suite());
        suite.addTest(SMIMEMiscTest.suite());
        return suite;
    }
}
