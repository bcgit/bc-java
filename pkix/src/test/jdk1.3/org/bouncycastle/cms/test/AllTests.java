package org.bouncycastle.cms.test;

import junit.framework.Test;
import junit.framework.TestSuite;

import javax.crypto.Cipher;
import java.security.Security;

public class AllTests 
{
    public static void main (String[] args) 
        throws Exception
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite() 
        throws Exception
    {
        TestSuite suite = new TestSuite("CMS tests");

        suite.addTest(NewCompressedDataTest.suite());
        suite.addTest(NewSignedDataTest.suite());
        suite.addTest(NewEnvelopedDataTest.suite());
        suite.addTest(NewAuthenticatedDataTest.suite());
        suite.addTest(NewAuthenticatedDataStreamTest.suite());
        suite.addTest(NewCompressedDataStreamTest.suite());
        suite.addTest(NewSignedDataStreamTest.suite());
        suite.addTest(NewEnvelopedDataStreamTest.suite());

        suite.addTest(MiscDataStreamTest.suite());
        suite.addTest(Rfc4134Test.suite());
        suite.addTest(ConverterTest.suite());

        suite.addTest(BcEnvelopedDataTest.suite());
        suite.addTest(BcSignedDataTest.suite());

        return suite;
    }
}
