package org.bouncycastle.jce.provider.test;
 
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import org.bouncycastle.jce.cert.CertPath;
import org.bouncycastle.jce.cert.CertPathBuilder;
import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CertificateFactory;
import org.bouncycastle.jce.cert.CollectionCertStoreParameters;
import org.bouncycastle.jce.cert.PKIXBuilderParameters;
import org.bouncycastle.jce.cert.PKIXCertPathBuilderResult;
import org.bouncycastle.jce.cert.TrustAnchor;
import java.security.cert.X509CRL;
import org.bouncycastle.jce.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class CertPathBuilderTest
    implements Test
{

    public TestResult baseTest()
    {
        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

                // initialise CertStore
            X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.rootCertBin));
            X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.interCertBin));
            X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(CertPathTest.finalCertBin));
            X509CRL rootCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(CertPathTest.rootCrlBin));
            X509CRL interCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(CertPathTest.interCrlBin));
            List list = new ArrayList();
            list.add(rootCert);
            list.add(interCert);
            list.add(finalCert);
            list.add(rootCrl);
            list.add(interCrl);
            CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
            CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
            Calendar validDate = Calendar.getInstance();
            validDate.set(2002,2,21,2,21,10);

                //Searching for rootCert by subjectDN without CRL
            Set trust = new HashSet();
            trust.add(new TrustAnchor(rootCert, null));

            CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX","BC");
            X509CertSelector targetConstraints = new X509CertSelector();
            targetConstraints.setSubject(PrincipalUtil.getSubjectX509Principal(finalCert).getEncoded());
            PKIXBuilderParameters params = new PKIXBuilderParameters(trust, targetConstraints);
            params.addCertStore(store);
            params.setDate(validDate.getTime());
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) cpb.build(params);
            CertPath                  path = result.getCertPath();
            
            if (path.getCertificates().size() != 2)
            {
                return new SimpleTestResult(false, this.getName() + ": wrong number of certs in baseTest path");
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, this.getName() + ": exception - " + e.toString(), e);
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    public TestResult v0Test()
    {
        try
        {
            // create certificates and CRLs
            KeyPair         rootPair = TestUtils.generateRSAKeyPair();
            KeyPair         interPair = TestUtils.generateRSAKeyPair();
            KeyPair         endPair = TestUtils.generateRSAKeyPair();
            
            X509Certificate rootCert = TestUtils.generateRootCert(rootPair);
            X509Certificate interCert = TestUtils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
            X509Certificate endCert = TestUtils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);
            
            BigInteger      revokedSerialNumber = BigInteger.valueOf(2);
            X509CRL         rootCRL = TestUtils.createCRL(rootCert, rootPair.getPrivate(), revokedSerialNumber);
            X509CRL         interCRL = TestUtils.createCRL(interCert, interPair.getPrivate(), revokedSerialNumber);
            
            // create CertStore to support path building
            List list = new ArrayList();
            
            list.add(rootCert);
            list.add(interCert);
            list.add(endCert);
            list.add(rootCRL);
            list.add(interCRL);
            
            CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
            CertStore                     store = CertStore.getInstance("Collection", params);
    
            // build the path
            CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
            X509CertSelector pathConstraints = new X509CertSelector();
            
            pathConstraints.setSubject(PrincipalUtil.getSubjectX509Principal(endCert).getEncoded());
            
            PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);
            
            buildParams.addCertStore(store);
            buildParams.setDate(new Date());
            
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
            CertPath                  path = result.getCertPath();
            
            if (path.getCertificates().size() != 2)
            {
                return new SimpleTestResult(false, this.getName() + ": wrong number of certs in v0Test path");
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, this.getName() + ": exception - " + e.toString(), e);
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.util.test.Test#perform()
     */
    public TestResult perform()
    {
        TestResult res = baseTest();
        if (!res.isSuccessful())
        {
            return res;
        }
        
        return v0Test();
    }
    
    public String getName()
    {
        return "CertPathBuilder";
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new CertPathBuilderTest();
        TestResult        result = test.perform();

        System.out.println(result.toString());
    }
}

