package org.bouncycastle.jce.provider.test;
 
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class CertPathValidatorTest
    implements Test
{

    public TestResult perform()
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
            list.add( rootCert );
            list.add( interCert );
            list.add( finalCert );
            list.add( rootCrl );
            list.add( interCrl );
            CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters( list );
            CertStore store = CertStore.getInstance("Collection", ccsp );
            Calendar validDate = Calendar.getInstance();
            validDate.set(2002,2,21,2,21,10);

                //validating path
            List certchain = new ArrayList();
            certchain.add( finalCert );
            certchain.add( interCert );
            CertPath cp = CertificateFactory.getInstance("X.509","BC").generateCertPath( certchain );
            Set trust = new HashSet();
            trust.add( new TrustAnchor( rootCert, null ) );

            CertPathValidator cpv = CertPathValidator.getInstance("PKIX","BC");
            PKIXParameters param = new PKIXParameters( trust );
            param.addCertStore(store);
            param.setDate( validDate.getTime() );
            PKIXCertPathValidatorResult result =
                (PKIXCertPathValidatorResult) cpv.validate(cp, param);
            PolicyNode policyTree = result.getPolicyTree();
            PublicKey subjectPublicKey = result.getPublicKey();
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return new SimpleTestResult(false, this.getName() + ": exception - " + e.toString());
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    public String getName()
    {
        return "CertPathValidator";
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new CertPathValidatorTest();
        TestResult        result = test.perform();

        System.out.println(result.toString());
    }
}

