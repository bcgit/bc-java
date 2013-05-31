package org.bouncycastle.jce.provider.test;

import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.X509AttributeCertStoreSelector;
import org.bouncycastle.x509.X509AttributeCertificate;
import org.bouncycastle.x509.X509CRLStoreSelector;
import org.bouncycastle.x509.X509CertPairStoreSelector;
import org.bouncycastle.x509.X509CertStoreSelector;
import org.bouncycastle.x509.X509CertificatePair;
import org.bouncycastle.x509.X509CollectionStoreParameters;
import org.bouncycastle.x509.X509Store;
import org.bouncycastle.x509.X509V2AttributeCertificate;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class X509StoreTest
    extends SimpleTest
{
    private void certPairTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509",
                "BC");

        X509Certificate rootCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.rootCertBin));
        X509Certificate interCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.interCertBin));
        X509Certificate finalCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.finalCertBin));

        // Testing CollectionCertStore generation from List
        X509CertificatePair pair1 = new X509CertificatePair(rootCert, interCert);
        List certList = new ArrayList();

        certList.add(pair1);
        certList.add(new X509CertificatePair(interCert, finalCert));

        X509CollectionStoreParameters ccsp = new X509CollectionStoreParameters(certList);

        X509Store certStore = X509Store.getInstance("CertificatePair/Collection", ccsp, "BC");
        X509CertPairStoreSelector selector = new X509CertPairStoreSelector();
        X509CertStoreSelector fwSelector = new X509CertStoreSelector();

        fwSelector.setSerialNumber(rootCert.getSerialNumber());
        fwSelector.setSubject(rootCert.getIssuerDN().getName());
        
        selector.setForwardSelector(fwSelector);

        Collection col = certStore.getMatches(selector);

        if (col.size() != 1 || !col.contains(pair1))
        {
            fail("failed pair1 test");
        }

        col = certStore.getMatches(null);

        if (col.size() != 2)
        {
            fail("failed null test");
        }
    }

    public void performTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509",
                "BC");

        X509Certificate rootCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.rootCertBin));
        X509Certificate interCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.interCertBin));
        X509Certificate finalCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.finalCertBin));
        X509CRL rootCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(
                CertPathTest.rootCrlBin));
        X509CRL interCrl = (X509CRL)cf
                .generateCRL(new ByteArrayInputStream(
                        CertPathTest.interCrlBin));

        // Testing CollectionCertStore generation from List
        List certList = new ArrayList();
        certList.add(rootCert);
        certList.add(interCert);
        certList.add(finalCert);
        X509CollectionStoreParameters ccsp = new X509CollectionStoreParameters(certList);
        X509Store certStore = X509Store.getInstance("Certificate/Collection", ccsp, "BC");
        // set default to be the same as for SUN X500 name
        X509Principal.DefaultReverse = true;

        // Searching for rootCert by subjectDN
    
        X509CertStoreSelector targetConstraints = new X509CertStoreSelector();
        targetConstraints.setSubject(PrincipalUtil.getSubjectX509Principal(rootCert).getEncoded());
        Collection certs = certStore.getMatches(targetConstraints);
        if (certs.size() != 1 || !certs.contains(rootCert))
        {
            fail("rootCert not found by subjectDN");
        }

        // Searching for rootCert by subjectDN encoded as byte
        targetConstraints = new X509CertStoreSelector();
        targetConstraints.setSubject(PrincipalUtil.getSubjectX509Principal(rootCert).getEncoded());
        certs = certStore.getMatches(targetConstraints);
        if (certs.size() != 1 || !certs.contains(rootCert))
        {
            fail("rootCert not found by encoded subjectDN");
        }

        X509Principal.DefaultReverse = false;

        // Searching for rootCert by public key encoded as byte
        targetConstraints = new X509CertStoreSelector();
        targetConstraints.setSubjectPublicKey(rootCert.getPublicKey().getEncoded());
        certs = certStore.getMatches(targetConstraints);
        if (certs.size() != 1 || !certs.contains(rootCert))
        {
            fail("rootCert not found by encoded public key");
        }

        // Searching for interCert by issuerDN
        targetConstraints = new X509CertStoreSelector();
        targetConstraints.setIssuer(PrincipalUtil.getSubjectX509Principal(rootCert).getEncoded());
        certs = certStore.getMatches(targetConstraints);
        if (certs.size() != 2)
        {
            fail("did not found 2 certs");
        }
        if (!certs.contains(rootCert))
        {
            fail("rootCert not found");
        }
        if (!certs.contains(interCert))
        {
            fail("interCert not found");
        }

        // Searching for rootCrl by issuerDN
        List crlList = new ArrayList();
        crlList.add(rootCrl);
        crlList.add(interCrl);
        ccsp = new X509CollectionStoreParameters(crlList);
        X509Store store = X509Store.getInstance("CRL/Collection", ccsp, "BC");
        X509CRLStoreSelector targetConstraintsCRL = new X509CRLStoreSelector();
        targetConstraintsCRL.setIssuers(Collections.singleton(rootCrl.getIssuerX500Principal()));
        Collection crls = store.getMatches(targetConstraintsCRL);
        if (crls.size() != 1 || !crls.contains(rootCrl))
        {
            fail("rootCrl not found");
        }

        crls = certStore.getMatches(targetConstraintsCRL);
        if (crls.size() != 0)
        {
            fail("error using wrong selector (CRL)");
        }
        certs = store.getMatches(targetConstraints);
        if (certs.size() != 0)
        {
            fail("error using wrong selector (certs)");
        }
        // Searching for attribute certificates
        X509V2AttributeCertificate attrCert = new X509V2AttributeCertificate(AttrCertTest.attrCert);
        X509AttributeCertificate attrCert2 = new X509V2AttributeCertificate(AttrCertTest.certWithBaseCertificateID);

        List attrList = new ArrayList();
        attrList.add(attrCert);
        attrList.add(attrCert2);
        ccsp = new X509CollectionStoreParameters(attrList);
        store = X509Store.getInstance("AttributeCertificate/Collection", ccsp, "BC");
        X509AttributeCertStoreSelector attrSelector = new X509AttributeCertStoreSelector();
        attrSelector.setHolder(attrCert.getHolder());
        if (!attrSelector.getHolder().equals(attrCert.getHolder()))
        {
            fail("holder get not correct");
        }
        Collection attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert))
        {
            fail("attrCert not found on holder");
        }
        attrSelector.setHolder(attrCert2.getHolder());
        if (attrSelector.getHolder().equals(attrCert.getHolder()))
        {
            fail("holder get not correct");
        }
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert2))
        {
            fail("attrCert2 not found on holder");
        }
        attrSelector = new X509AttributeCertStoreSelector();
        attrSelector.setIssuer(attrCert.getIssuer());
        if (!attrSelector.getIssuer().equals(attrCert.getIssuer()))
        {
            fail("issuer get not correct");
        }
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert))
        {
            fail("attrCert not found on issuer");
        }
        attrSelector.setIssuer(attrCert2.getIssuer());
        if (attrSelector.getIssuer().equals(attrCert.getIssuer()))
        {
            fail("issuer get not correct");
        }
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert2))
        {
            fail("attrCert2 not found on issuer");
        }
        attrSelector = new X509AttributeCertStoreSelector();
        attrSelector.setAttributeCert(attrCert);
        if (!attrSelector.getAttributeCert().equals(attrCert))
        {
            fail("attrCert get not correct");
        }
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert))
        {
            fail("attrCert not found on attrCert");
        }
        attrSelector = new X509AttributeCertStoreSelector();
        attrSelector.setSerialNumber(attrCert.getSerialNumber());
        if (!attrSelector.getSerialNumber().equals(attrCert.getSerialNumber()))
        {
            fail("serial number get not correct");
        }
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert))
        {
            fail("attrCert not found on serial number");
        }
        attrSelector = (X509AttributeCertStoreSelector)attrSelector.clone();
        if (!attrSelector.getSerialNumber().equals(attrCert.getSerialNumber()))
        {
            fail("serial number get not correct");
        }
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert))
        {
            fail("attrCert not found on serial number");
        }

        attrSelector = new X509AttributeCertStoreSelector();
        attrSelector.setAttributeCertificateValid(attrCert.getNotBefore());
        if (!attrSelector.getAttributeCertificateValid().equals(attrCert.getNotBefore()))
        {
            fail("valid get not correct");
        }
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert))
        {
            fail("attrCert not found on valid");
        }
        attrSelector = new X509AttributeCertStoreSelector();
        attrSelector.setAttributeCertificateValid(new Date(attrCert.getNotBefore().getTime() - 100));
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 0)
        {
            fail("attrCert found on before");
        }
        attrSelector.setAttributeCertificateValid(new Date(attrCert.getNotAfter().getTime() + 100));
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 0)
        {
            fail("attrCert found on after");
        }
        attrSelector.setSerialNumber(BigInteger.valueOf(10000));
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 0)
        {
            fail("attrCert found on wrong serial number");
        }

        attrSelector.setAttributeCert(null);
        attrSelector.setAttributeCertificateValid(null);
        attrSelector.setHolder(null);
        attrSelector.setIssuer(null);
        attrSelector.setSerialNumber(null);
        if (attrSelector.getAttributeCert() != null)
        {
            fail("null attrCert");
        }
        if (attrSelector.getAttributeCertificateValid() != null)
        {
            fail("null attrCertValid");
        }
        if (attrSelector.getHolder() != null)
        {
            fail("null attrCert holder");
        }
        if (attrSelector.getIssuer() != null)
        {
            fail("null attrCert issuer");
        }
        if (attrSelector.getSerialNumber() != null)
        {
            fail("null attrCert serial");
        }

        attrs = certStore.getMatches(attrSelector);
        if (attrs.size() != 0)
        {
            fail("error using wrong selector (attrs)");
        }

        certPairTest();
    }

    public String getName()
    {
        return "X509Store";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new X509StoreTest());
    }

}
