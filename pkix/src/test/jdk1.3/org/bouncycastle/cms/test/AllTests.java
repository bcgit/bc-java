package org.bouncycastle.cms.test;

import junit.framework.Test;
import junit.framework.TestSuite;

import javax.crypto.Cipher;
import java.security.Security;
import org.bouncycastle.test.PrintTestResult;


public class AllTests 
{
    public static void main (String[] args) 
        throws Exception
    {
        PrintTestResult.printResult( junit.textui.TestRunner.run(suite()));
    }
    
    public static Test suite() 
        throws Exception
    {
        TestSuite suite = new TestSuite("CMS tests");

        // NOTE: jdk1.3 overlay. NewSignedDataTest / NewSignedDataStreamTest are excluded from the
        // jdk1.3 build (java.security.cert.X509Certificate.getIssuerX500Principal() etc., Java
        // 1.4 APIs, ant/jdk13.xml).
        suite.addTest(NewCompressedDataTest.suite());
        suite.addTest(NewEnvelopedDataTest.suite());
        suite.addTest(NewAuthenticatedDataTest.suite());
        suite.addTest(NewAuthenticatedDataStreamTest.suite());
        suite.addTest(NewCompressedDataStreamTest.suite());
        suite.addTest(NewEnvelopedDataStreamTest.suite());

        suite.addTest(MiscDataStreamTest.suite());
        suite.addTest(Rfc4134Test.suite());
        suite.addTest(ConverterTest.suite());

        suite.addTest(BcEnvelopedDataTest.suite());
        suite.addTest(BcSignedDataTest.suite());

        return suite;
    }
}
