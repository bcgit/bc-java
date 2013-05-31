package org.bouncycastle.cms.test;

import javax.crypto.Cipher;

import junit.framework.Test;
import junit.framework.TestSuite;

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

        suite.addTest(AuthenticatedDataTest.suite());
        suite.addTest(AuthenticatedDataStreamTest.suite());
        suite.addTest(CompressedDataTest.suite());
        suite.addTest(NewCompressedDataTest.suite());
        suite.addTest(SignedDataTest.suite());
        suite.addTest(NewSignedDataTest.suite());
        suite.addTest(EnvelopedDataTest.suite());
        suite.addTest(NewEnvelopedDataTest.suite());
        suite.addTest(NewAuthenticatedDataTest.suite());
        suite.addTest(NewAuthenticatedDataStreamTest.suite());
        suite.addTest(CompressedDataStreamTest.suite());
        suite.addTest(NewCompressedDataStreamTest.suite());
        suite.addTest(SignedDataStreamTest.suite());
        suite.addTest(NewSignedDataStreamTest.suite());
        suite.addTest(EnvelopedDataStreamTest.suite());
        suite.addTest(NewEnvelopedDataStreamTest.suite());

        suite.addTest(MiscDataStreamTest.suite());
        suite.addTest(Rfc4134Test.suite());
        suite.addTest(ConverterTest.suite());

        suite.addTest(BcEnvelopedDataTest.suite());
        suite.addTest(BcSignedDataTest.suite());

        try
        {
            Cipher.getInstance("RSA", "SunJCE");

            suite.addTest(SunProviderTest.suite());
            suite.addTest(NullProviderTest.suite());
        }
        catch (Exception e)
        {
            // ignore
        }

        return suite;
    }
}
