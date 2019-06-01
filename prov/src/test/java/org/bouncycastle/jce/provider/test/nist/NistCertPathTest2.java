package org.bouncycastle.jce.provider.test.nist;

import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Extension;

/**
 * NIST CertPath test data for RFC 3280
 */
public class NistCertPathTest2
    extends TestCase
{
    private static final String ANY_POLICY = "2.5.29.32.0";
    private static final String NIST_TEST_POLICY_1 = "2.16.840.1.101.3.2.1.48.1";
    private static final String NIST_TEST_POLICY_2 = "2.16.840.1.101.3.2.1.48.2";
    private static final String NIST_TEST_POLICY_3 = "2.16.840.1.101.3.2.1.48.3";
    
    private static Map   certs = new HashMap();
    private static Map   crls = new HashMap();
    
    private static Set   noPolicies = Collections.EMPTY_SET;
    private static Set   anyPolicy = Collections.singleton(ANY_POLICY);
    private static Set   nistTestPolicy1 = Collections.singleton(NIST_TEST_POLICY_1);
    private static Set   nistTestPolicy2 = Collections.singleton(NIST_TEST_POLICY_2);
    private static Set   nistTestPolicy3 = Collections.singleton(NIST_TEST_POLICY_3);
    private static Set   nistTestPolicy1And2 = new HashSet(Arrays.asList(new String[] { NIST_TEST_POLICY_1, NIST_TEST_POLICY_2 }));
    
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    // 4.13
    public void testValidDNnameConstraintsTest1()
        throws Exception
    {
        doTest("TrustAnchorRootCertificate",
                new String[] { "ValidDNnameConstraintsTest1EE", "nameConstraintsDN1CACert" },
                new String[] { "nameConstraintsDN1CACRL", "TrustAnchorRootCRL" });
    }

    public void testInvalidDNnameConstraintsTest2()
        throws Exception
    {
        doExceptionTest("TrustAnchorRootCertificate",
            new String[]{"InvalidDNnameConstraintsTest2EE", "nameConstraintsDN1CACert"},
            new String[]{"nameConstraintsDN1CACRL", "TrustAnchorRootCRL"},
            0,
            "Subtree check for certificate subject failed.");
    }

    public void testInvalidDNnameConstraintsTest3()
        throws Exception
    {
        doExceptionTest("TrustAnchorRootCertificate",
            new String[]{"InvalidDNnameConstraintsTest3EE", "nameConstraintsDN1CACert"},
            new String[]{"nameConstraintsDN1CACRL", "TrustAnchorRootCRL"},
            0,
            "Subtree check for certificate subject alternative name failed.");
    }

    public void testValidDNnameConstraintsTest4()
        throws Exception
    {
        doTest("TrustAnchorRootCertificate",
                new String[] { "ValidDNnameConstraintsTest4EE", "nameConstraintsDN1CACert" },
                new String[] { "nameConstraintsDN1CACRL", "TrustAnchorRootCRL" });
    }

    public void testValidDNnameConstraintsTest5()
        throws Exception
    {
        doTest("TrustAnchorRootCertificate",
                new String[] { "ValidDNnameConstraintsTest5EE", "nameConstraintsDN2CACert" },
                new String[] { "nameConstraintsDN2CACRL", "TrustAnchorRootCRL" });
    }

    public void testValidDNnameConstraintsTest6()
        throws Exception
    {
        doTest("TrustAnchorRootCertificate",
                new String[] { "ValidDNnameConstraintsTest6EE", "nameConstraintsDN3CACert" },
                new String[] { "nameConstraintsDN3CACRL", "TrustAnchorRootCRL" });
    }

    public void testInvalidDNnameConstraintsTest7()
        throws Exception
    {
        doExceptionTest("TrustAnchorRootCertificate",
            new String[]{"InvalidDNnameConstraintsTest7EE", "nameConstraintsDN3CACert"},
            new String[]{"nameConstraintsDN3CACRL", "TrustAnchorRootCRL"},
            0,
            "Subtree check for certificate subject failed.");
    }

    public void testInvalidDNnameConstraintsTest8()
        throws Exception
    {
        doExceptionTest("TrustAnchorRootCertificate",
            new String[]{"InvalidDNnameConstraintsTest8EE", "nameConstraintsDN4CACert"},
            new String[]{"nameConstraintsDN4CACRL", "TrustAnchorRootCRL"},
            0,
            "Subtree check for certificate subject failed.");
    }

    public void testInvalidDNnameConstraintsTest9()
        throws Exception
    {
        doExceptionTest("TrustAnchorRootCertificate",
            new String[]{"InvalidDNnameConstraintsTest9EE", "nameConstraintsDN4CACert"},
            new String[]{"nameConstraintsDN4CACRL", "TrustAnchorRootCRL"},
            0,
            "Subtree check for certificate subject failed.");
    }

    public void testInvalidDNnameConstraintsTest10()
        throws Exception
    {
        doExceptionTest("TrustAnchorRootCertificate",
            new String[]{"InvalidDNnameConstraintsTest10EE", "nameConstraintsDN5CACert"},
            new String[]{"nameConstraintsDN5CACRL", "TrustAnchorRootCRL"},
            0,
            "Subtree check for certificate subject failed.");
    }

    public void testValidDNnameConstraintsTest11()
        throws Exception
    {
        doTest("TrustAnchorRootCertificate",
                new String[] { "ValidDNnameConstraintsTest11EE", "nameConstraintsDN5CACert" },
                new String[] { "nameConstraintsDN5CACRL", "TrustAnchorRootCRL" });
    }

    public void testInvalidDNnameConstraintsTest12()
        throws Exception
    {
        doExceptionTest("TrustAnchorRootCertificate",
            new String[]{"InvalidDNnameConstraintsTest10EE", "nameConstraintsDN5CACert"},
            new String[]{"nameConstraintsDN5CACRL", "TrustAnchorRootCRL"},
            0,
            "Subtree check for certificate subject failed.");
    }

    public void testInvalidDNnameConstraintsTest13()
        throws Exception
    {
        doExceptionTest("TrustAnchorRootCertificate",
            new String[]{"InvalidDNnameConstraintsTest13EE", "nameConstraintsDN1subCA2Cert", "nameConstraintsDN1CACert"},
            new String[]{"nameConstraintsDN1subCA2CRL", "nameConstraintsDN1CACRL", "TrustAnchorRootCRL"},
            0,
            "Subtree check for certificate subject failed.");
    }

    public void testValidDNnameConstraintsTest14()
        throws Exception
    {
        doTest("TrustAnchorRootCertificate",
                new String[] { "ValidDNnameConstraintsTest14EE", "nameConstraintsDN1subCA2Cert", "nameConstraintsDN1CACert" },
                new String[] { "nameConstraintsDN1subCA2CRL", "nameConstraintsDN1CACRL", "TrustAnchorRootCRL" });
    }

    public void testInvalidDNnameConstraintsTest15()
        throws Exception
    {
        doExceptionTest("TrustAnchorRootCertificate",
            new String[]{"InvalidDNnameConstraintsTest15EE", "nameConstraintsDN3subCA1Cert", "nameConstraintsDN3CACert"},
            new String[]{"nameConstraintsDN3subCA1CRL", "nameConstraintsDN3CACRL", "TrustAnchorRootCRL"},
            0,
            "Subtree check for certificate subject failed.");
    }

    public void testInvalidDNnameConstraintsTest16()
        throws Exception
    {
        doExceptionTest("TrustAnchorRootCertificate",
            new String[]{"InvalidDNnameConstraintsTest16EE", "nameConstraintsDN3subCA1Cert", "nameConstraintsDN3CACert"},
            new String[]{"nameConstraintsDN3subCA1CRL", "nameConstraintsDN3CACRL", "TrustAnchorRootCRL"},
            0,
            "Subtree check for certificate subject failed.");
    }

    public void testInvalidDNnameConstraintsTest17()
        throws Exception
    {
        doExceptionTest("TrustAnchorRootCertificate",
            new String[]{"InvalidDNnameConstraintsTest17EE", "nameConstraintsDN3subCA2Cert", "nameConstraintsDN3CACert"},
            new String[]{"nameConstraintsDN3subCA2CRL", "nameConstraintsDN3CACRL", "TrustAnchorRootCRL"},
            0,
            "Subtree check for certificate subject failed.");
    }

    public void testValidDNnameConstraintsTest18()
        throws Exception
    {
        doTest("TrustAnchorRootCertificate",
                new String[] { "ValidDNnameConstraintsTest18EE", "nameConstraintsDN3subCA2Cert", "nameConstraintsDN3CACert" },
                new String[] { "nameConstraintsDN3subCA2CRL", "nameConstraintsDN3CACRL", "TrustAnchorRootCRL" });
    }

    public void testValidDNnameConstraintsTest19()
        throws Exception
    {
        doBuilderTest("TrustAnchorRootCertificate",
                new String[] { "ValidDNnameConstraintsTest19EE", "nameConstraintsDN1SelfIssuedCACert", "nameConstraintsDN1CACert" },
                new String[] { "nameConstraintsDN1CACRL", "TrustAnchorRootCRL" },
            null, false, false);
    }

    public void testInvalidDNnameConstraintsTest20()
        throws Exception
    {
        doExceptionTest("TrustAnchorRootCertificate",
            new String[]{"InvalidDNnameConstraintsTest20EE", "nameConstraintsDN1CACert"},
            new String[]{"nameConstraintsDN1CACRL", "TrustAnchorRootCRL"},
            0,
            "CertPath for CRL signer failed to validate.");   // due to a subtree failure
    }

    private void doExceptionTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls,
        int         index,
        String      message)
        throws Exception
    {
        try
        {
            doTest(trustAnchor, certs, crls);
            
            fail("path accepted when should be rejected");
        }
        catch (CertPathValidatorException e)
        {                    
            assertEquals(index, e.getIndex());
            assertEquals(message, e.getMessage());
        }
    }
    
    private void doExceptionTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls,
        Set         policies,
        int         index,
        String      message)
        throws Exception
    {
        try
        {
            doTest(trustAnchor, certs, crls, policies);
            
            fail("path accepted when should be rejected");
        }
        catch (CertPathValidatorException e)
        {
            assertEquals(index, e.getIndex());
            assertEquals(message, e.getMessage());
        }
    }

    private void doExceptionTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls,
        int         index,
        String      mesStart,
        String      mesEnd)
        throws Exception
    {
        try
        {
            doTest(trustAnchor, certs, crls);
            
            fail("path accepted when should be rejected");
        }
        catch (CertPathValidatorException e)
        {
            assertEquals(index, e.getIndex());
            assertTrue(e.getMessage().startsWith(mesStart));
            assertTrue(e.getMessage().endsWith(mesEnd));
        }
    }
    
    private PKIXCertPathValidatorResult doTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls)
        throws Exception
    {
        return doTest(trustAnchor, certs, crls, null);
    }
    
    private PKIXCertPathValidatorResult doTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls,
        Set         policies)
        throws Exception
    {
        Set  trustedSet = Collections.singleton(getTrustAnchor(trustAnchor));
        List certsAndCrls = new ArrayList();
        X509Certificate endCert = loadCert(certs[certs.length - 1]);
        
        for (int i = 0; i != certs.length - 1; i++)
        {
            certsAndCrls.add(loadCert(certs[i]));
        }
        
        certsAndCrls.add(endCert);

        CertPath certPath = CertificateFactory.getInstance("X.509","BC").generateCertPath(certsAndCrls);
          
        for (int i = 0; i != crls.length; i++)
        {
            certsAndCrls.add(loadCrl(crls[i]));
        }
    
        CertStore  store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certsAndCrls), "BC");
        
        CertPathValidator validator = CertPathValidator.getInstance("PKIX","BC");
        PKIXParameters    params = new PKIXParameters(trustedSet);
        
        params.addCertStore(store);
        params.setRevocationEnabled(true);
        params.setDate(new GregorianCalendar(2010, 1, 1).getTime());

        if (policies != null)
        {
            params.setExplicitPolicyRequired(true);
            params.setInitialPolicies(policies);
        }
        
        return (PKIXCertPathValidatorResult)validator.validate(certPath, params);
    }

    private PKIXCertPathBuilderResult doBuilderTest(
        String trustAnchor,
        String[] certs,
        String[] crls,
        Set initialPolicies,
        boolean policyMappingInhibited,
        boolean anyPolicyInhibited)
        throws Exception
    {
        Set  trustedSet = Collections.singleton(getTrustAnchor(trustAnchor));
        List certsAndCrls = new ArrayList();
        X509Certificate endCert = loadCert(certs[certs.length - 1]);
        
        for (int i = 0; i != certs.length - 1; i++)
        {
            certsAndCrls.add(loadCert(certs[i]));
        }
        
        certsAndCrls.add(endCert);

        for (int i = 0; i != crls.length; i++)
        {
            certsAndCrls.add(loadCrl(crls[i]));
        }
    
        CertStore  store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certsAndCrls), "BC");

        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");

        X509CertSelector endSelector = new X509CertSelector();

        endSelector.setCertificate(endCert);

        PKIXBuilderParameters builderParams = new PKIXBuilderParameters(trustedSet, endSelector);

        if (initialPolicies != null)
        {
            builderParams.setInitialPolicies(initialPolicies);
            builderParams.setExplicitPolicyRequired(true);
        }
        if (policyMappingInhibited)
        {
            builderParams.setPolicyMappingInhibited(policyMappingInhibited);
        }
        if (anyPolicyInhibited)
        {
            builderParams.setAnyPolicyInhibited(anyPolicyInhibited);
        }

        builderParams.addCertStore(store);
        builderParams.setDate(new GregorianCalendar(2010, 1, 1).getTime());

        try
        {
            return (PKIXCertPathBuilderResult)builder.build(builderParams);
        }
        catch (CertPathBuilderException e)
        {
            throw (Exception)e.getCause();
        }
    }

    private X509Certificate loadCert(
        String certName)
    {
        X509Certificate cert = (X509Certificate)certs.get(certName);
        
        if (cert != null)
        {
            return cert;
        }
        
        try
        {
            InputStream in = this.getClass().getResourceAsStream(getPkitsHome() + "/certs/" + certName + ".crt");

            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
            
            cert = (X509Certificate)fact.generateCertificate(in);
    
            certs.put(certName, cert);
            
            return cert;
        }
        catch (Exception e)
        {
            throw new IllegalStateException("exception loading certificate " + certName + ": " + e);
        }
    }
    
    private X509CRL loadCrl(
        String crlName)
        throws Exception
    {
        X509CRL crl = (X509CRL)crls.get(crlName);
        
        if (crl != null)
        {
            return crl;
        }
        
        try
        {
            InputStream in = this.getClass().getResourceAsStream(getPkitsHome() + "/crls/" + crlName + ".crl");
            
            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
            
            crl = (X509CRL)fact.generateCRL(in);
            
            crls.put(crlName, crl);
            
            return crl;
        }
        catch (Exception e)
        {
            throw new IllegalStateException("exception loading CRL: " + crlName);
        }
    }

    private TrustAnchor getTrustAnchor(String trustAnchorName)
        throws Exception
    {
        X509Certificate cert = loadCert(trustAnchorName);
        byte[]          extBytes = cert.getExtensionValue(Extension.nameConstraints.getId());
        
        if (extBytes != null)
        {
            ASN1Encodable extValue = ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(extBytes).getOctets());
            
            return new TrustAnchor(cert, extValue.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        }
        
        return new TrustAnchor(cert, null);
    }
    
    private String getPkitsHome()
    {
        return "/PKITS";
    }
    
    public static void main (String[] args) 
        throws Exception
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite() 
        throws Exception
    {   
        TestSuite suite = new TestSuite("NIST CertPath Tests");
        
        suite.addTestSuite(NistCertPathTest2.class);
        
        return suite;
    }
}
