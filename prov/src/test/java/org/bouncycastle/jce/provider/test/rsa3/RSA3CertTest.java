package org.bouncycastle.jce.provider.test.rsa3;

import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Marius Schilder's Bleichenbacher's Forgery Attack Tests
 */
public class RSA3CertTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }
    
    public void testA()
        throws Exception
    {
        doTest("self-testcase-A.pem");
    }

    public void testB()
        throws Exception
    {
        doTest("self-testcase-B.pem");
    }
    
    public void testC()
        throws Exception
    {
        doTest("self-testcase-C.pem");
    }
    
    public void testD()
        throws Exception
    {
        doTest("self-testcase-D.pem");
    }
    
    public void testE()
        throws Exception
    {
        doTest("self-testcase-E.pem");
    }
    
    public void testF()
        throws Exception
    {
        doTest("self-testcase-F.pem");
    }
    
    public void testG()
        throws Exception
    {
        doTest("self-testcase-G.pem");
    }
    
    public void testH()
        throws Exception
    {
        doTest("self-testcase-H.pem");
    }
    
    public void testI()
        throws Exception
    {
        doTest("self-testcase-I.pem");
    }
    
    public void testJ()
        throws Exception
    {
        doTest("self-testcase-J.pem");
    }
    
    public void testL()
        throws Exception
    {
        doTest("self-testcase-L.pem");
    }
    
    private void doTest(
        String      certName)
        throws Exception
    {
        X509Certificate  cert = loadCert(certName);
        byte[]           tbs = cert.getTBSCertificate();
        Signature        sig = Signature.getInstance(cert.getSigAlgName(), "BC");
        
        sig.initVerify(cert.getPublicKey());
        
        sig.update(tbs);
        
        assertFalse(sig.verify(cert.getSignature()));
    }

    private X509Certificate loadCert(
        String certName)
        throws Exception
    {
        CertificateFactory rd = CertificateFactory.getInstance("X.509", "BC");
        
        return (X509Certificate)rd.generateCertificate(getClass().getResourceAsStream(certName));
    }
    
    public static void main (String[] args) 
        throws Exception
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite() 
        throws Exception
    {   
        TestSuite suite = new TestSuite("Bleichenbacher's Forgery Attack Tests");
        
        suite.addTestSuite(RSA3CertTest.class);
        
        return suite;
    }
}
