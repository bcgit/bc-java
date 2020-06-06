package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class CertPathBuilderTest
    extends SimpleTest
{

    private void baseTest()
        throws Exception
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
        Date validDate = new Date(rootCrl.getThisUpdate().getTime() + 60 * 60 * 1000);

            //Searching for rootCert by subjectDN without CRL
        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX","BC");
        X509CertSelector targetConstraints = new X509CertSelector();
        targetConstraints.setSubject(finalCert.getSubjectX500Principal().getEncoded());
        PKIXBuilderParameters params = new PKIXBuilderParameters(trust, targetConstraints);
        params.addCertStore(store);
        params.setDate(validDate);
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) cpb.build(params);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 2)
        {
            fail("wrong number of certs in baseTest path");
        }
    }

    private void v0Test()
        throws Exception
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

        pathConstraints.setSubject(endCert.getSubjectX500Principal().getEncoded());

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date());

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 2)
        {
            fail("wrong number of certs in v0Test path");
        }
    }

    private void eeInSelectorTest()
        throws Exception
    {
        // create certificates and CRLs
        KeyPair         rootPair = TestUtils.generateRSAKeyPair();
        KeyPair         interPair = TestUtils.generateRSAKeyPair();
        KeyPair         endPair = TestUtils.generateRSAKeyPair();

        X509Certificate rootCert = TestUtils.generateRootCert(rootPair);
        X509Certificate interCert = TestUtils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
        X509Certificate endCert = TestUtils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);

        // create CertStore to support path building
        List list = new ArrayList();

        list.add(interCert);
        list.add(endCert);
        
        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setCertificate(endCert);

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date());
        buildParams.setRevocationEnabled(false);

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 2)
        {
            fail("wrong number of certs in v0Test path");
        }
    }

    private void eeOnlyInSelectorTest()
        throws Exception
    {
        // create certificates and CRLs
        KeyPair         rootPair = TestUtils.generateRSAKeyPair();
        KeyPair         interPair = TestUtils.generateRSAKeyPair();
        KeyPair         endPair = TestUtils.generateRSAKeyPair();
        KeyPair         miscPair = TestUtils.generateRSAKeyPair();

        X509Certificate rootCert = TestUtils.generateRootCert(rootPair);
        X509Certificate interCert = TestUtils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
        X509Certificate endCert = TestUtils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);
        X509Certificate miscCert = TestUtils.generateEndEntityCert(miscPair.getPublic(), interPair.getPrivate(), interCert);

        // create CertStore to support path building
        List list = new ArrayList();

        list.add(interCert);
        list.add(miscCert);

        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setCertificate(endCert);

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date());
        buildParams.setRevocationEnabled(false);

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 2)
        {
            fail("wrong number of certs in v0Test path");
        }
    }

    public void performTest()
        throws Exception
    {
        baseTest();
        v0Test();
        eeInSelectorTest();
        eeOnlyInSelectorTest();
    }
    
    public String getName()
    {
        return "CertPathBuilder";
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CertPathBuilderTest());
    }
}

