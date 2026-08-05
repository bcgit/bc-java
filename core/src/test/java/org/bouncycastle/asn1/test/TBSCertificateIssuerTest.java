package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.Validity;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.test.SimpleTest;

public class TBSCertificateIssuerTest
    extends SimpleTest
{
    public String getName()
    {
        return "TBSCertificateIssuer";
    }

    public void performTest()
        throws IOException
    {
        parseRejectsEmptyIssuer();
        publicConstructorRejectsEmptyIssuer();
        v1GeneratorRejectsEmptyIssuer();
        v3GeneratorRejectsEmptyIssuer();
        allowEmptyIssuerPropertyTest();
    }

    private void allowEmptyIssuerPropertyTest()
        throws IOException
    {
        byte[] encoded = emptyIssuerTbs();

        System.setProperty(Properties.X509_ALLOW_EMPTY_ISSUER_CERT, "true");
        try
        {
            // the read-side concession for non-PKIX profiles (github #2387): the parse
            // accepts the empty issuer and round-trips the original encoding...
            TBSCertificate cert = TBSCertificate.getInstance(encoded);

            isTrue("issuer not empty", cert.getIssuer().size() == 0);
            isTrue("encoding not preserved", Arrays.areEqual(encoded, cert.getEncoded(ASN1Encoding.DER)));

            // ...the reviewer still reports the problem...
            List problems = TBSCertificate.reviewStructure(ASN1Sequence.getInstance(encoded));

            boolean found = false;
            for (int i = 0; i != problems.size(); i++)
            {
                if (((Exception)problems.get(i)).getMessage().indexOf("empty distinguished name") >= 0)
                {
                    found = true;
                }
            }
            isTrue("reviewer no longer reports empty issuer", found);

            // ...and generation stays strict.
            publicConstructorRejectsEmptyIssuer();
            v1GeneratorRejectsEmptyIssuer();
            v3GeneratorRejectsEmptyIssuer();
        }
        finally
        {
            System.getProperties().remove(Properties.X509_ALLOW_EMPTY_ISSUER_CERT);
        }
    }

    private static byte[] emptyIssuerTbs()
        throws IOException
    {
        // Build a v1 TBSCertificate with an empty issuer DN.
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(ASN1Integer.ONE);
        v.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")));
        v.add(new X500Name(new RDN[0]));
        v.add(validity());
        v.add(subjectName());
        v.add(spki());

        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    private void parseRejectsEmptyIssuer()
        throws IOException
    {
        byte[] encoded = emptyIssuerTbs();

        try
        {
            TBSCertificate.getInstance(encoded);
            fail("empty issuer DN accepted on parse");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("empty distinguished name") >= 0);
        }
    }

    private void publicConstructorRejectsEmptyIssuer()
    {
        try
        {
            new TBSCertificate(
                ASN1Integer.TWO,
                ASN1Integer.ONE,
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")),
                new X500Name(new RDN[0]),
                new Validity(notBefore(), notAfter()),
                subjectName(),
                spki(),
                null, null, null);
            fail("public constructor accepted empty issuer");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void v1GeneratorRejectsEmptyIssuer()
    {
        V1TBSCertificateGenerator gen = new V1TBSCertificateGenerator();
        gen.setSerialNumber(ASN1Integer.ONE);
        gen.setSignature(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")));
        gen.setIssuer(new X500Name(new RDN[0]));
        gen.setStartDate(notBefore());
        gen.setEndDate(notAfter());
        gen.setSubject(subjectName());
        gen.setSubjectPublicKeyInfo(spki());

        try
        {
            gen.generateTBSCertificate();
            fail("V1 generator accepted empty issuer");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    private void v3GeneratorRejectsEmptyIssuer()
    {
        V3TBSCertificateGenerator gen = new V3TBSCertificateGenerator();
        gen.setSerialNumber(ASN1Integer.ONE);
        gen.setSignature(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")));
        gen.setIssuer(new X500Name(new RDN[0]));
        gen.setStartDate(notBefore());
        gen.setEndDate(notAfter());
        gen.setSubject(subjectName());
        gen.setSubjectPublicKeyInfo(spki());

        try
        {
            gen.generateTBSCertificate();
            fail("V3 generator accepted empty issuer");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        try
        {
            gen.generatePreTBSCertificate();
            fail("V3 generator pre-tbs accepted empty issuer");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    private static Validity validity()
    {
        return new Validity(notBefore(), notAfter());
    }

    private static Time notBefore()
    {
        return new Time(new DERUTCTime("250101000000Z"));
    }

    private static Time notAfter()
    {
        return new Time(new DERUTCTime("260101000000Z"));
    }

    private static X500Name subjectName()
    {
        return new X500Name(
            new RDN[]{new RDN(org.bouncycastle.asn1.x500.style.BCStyle.CN,
                new org.bouncycastle.asn1.DERUTF8String("Subject"))});
    }

    private static SubjectPublicKeyInfo spki()
    {
        return new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.1")),
            new DERBitString(new byte[]{0}));
    }

    public static void main(String[] args)
    {
        runTest(new TBSCertificateIssuerTest());
    }
}
