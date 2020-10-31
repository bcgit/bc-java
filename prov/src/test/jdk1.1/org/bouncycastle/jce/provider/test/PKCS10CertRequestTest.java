package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 **/
public class PKCS10CertRequestTest
    implements Test
{
    public String getName()
    {
        return "PKCS10CertRequest";
    }

    public TestResult perform()
    {
        try
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

            kpg.initialize(512);

            KeyPair kp = kpg.generateKeyPair();

            Hashtable                   attrs = new Hashtable();

            attrs.put(X509Principal.C, "AU");
            attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
            attrs.put(X509Principal.L, "Melbourne");
            attrs.put(X509Principal.ST, "Victoria");
            attrs.put(X509Principal.EmailAddress, "feedback-crypto@bouncycastle.org");

            X509Name    subject = new X509Name(attrs);

            PKCS10CertificationRequest req1 = new PKCS10CertificationRequest(
                                                        "SHA1withRSA",
                                                        subject,
                                                        kp.getPublic(),
                                                        null,
                                                        kp.getPrivate());
                                
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ASN1OutputStream dOut = ASN1OutputStream.create(bOut, ASN1Encoding.DER);

            dOut.writeObject(req1);
            dOut.close();

            ByteArrayInputStream    bIn = new ByteArrayInputStream(bOut.toByteArray());
            ASN1InputStream          dIn = new ASN1InputStream(bIn);

            PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(
                                                    (ASN1Sequence)dIn.readObject());

            if (!req2.verify())
            {
                return new SimpleTestResult(false, getName() + ": Failed verify check.");
            }

            if (!req2.getPublicKey().equals(req1.getPublicKey()))
            {
                return new SimpleTestResult(false, getName() + ": Failed public key check.");
            }

            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
e.printStackTrace();
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new PKCS10CertRequestTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
