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
        
        suite.addTest(CompressedDataTest.suite());
        suite.addTest(SignedDataTest.suite());
        suite.addTest(EnvelopedDataTest.suite());

        suite.addTest(CompressedDataStreamTest.suite());
        suite.addTest(SignedDataStreamTest.suite());
        suite.addTest(EnvelopedDataStreamTest.suite());

        return suite;
    }
}
