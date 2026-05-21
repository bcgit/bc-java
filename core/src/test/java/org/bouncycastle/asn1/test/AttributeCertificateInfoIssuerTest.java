package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttCertIssuer;
import org.bouncycastle.asn1.x509.AttCertValidityPeriod;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.Holder;
import org.bouncycastle.asn1.x509.V2AttributeCertificateInfoGenerator;
import org.bouncycastle.asn1.x509.V2Form;
import org.bouncycastle.util.test.SimpleTest;

public class AttributeCertificateInfoIssuerTest
    extends SimpleTest
{
    public String getName()
    {
        return "AttributeCertificateInfoIssuer";
    }

    public void performTest()
        throws IOException
    {
        parseRejectsEmptyV1Issuer();
        parseRejectsEmptyV2Issuer();
        generatorRejectsEmptyIssuer();
    }

    private void parseRejectsEmptyV1Issuer()
        throws IOException
    {
        // v1 form: AttCertIssuer = empty GeneralNames sequence.
        byte[] encoded = buildAttrCertInfo(new DERSequence()).getEncoded(ASN1Encoding.DER);
        try
        {
            AttributeCertificateInfo.getInstance(encoded);
            fail("empty v1 GeneralNames issuer accepted");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("empty") >= 0);
        }
    }

    private void parseRejectsEmptyV2Issuer()
        throws IOException
    {
        // v2 form: V2Form with no issuerName/baseCertificateID/objectDigestInfo.
        byte[] encoded = buildAttrCertInfo(new DERTaggedObject(false, 0, new DERSequence()))
            .getEncoded(ASN1Encoding.DER);
        try
        {
            AttributeCertificateInfo.getInstance(encoded);
            fail("empty v2 V2Form issuer accepted");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("empty") >= 0);
        }
    }

    private void generatorRejectsEmptyIssuer()
    {
        V2AttributeCertificateInfoGenerator gen = new V2AttributeCertificateInfoGenerator();
        gen.setHolder(holder());
        gen.setIssuer(new AttCertIssuer(new V2Form(new GeneralNames(new GeneralName[0]))));
        gen.setSignature(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")));
        gen.setSerialNumber(ASN1Integer.ONE);
        gen.setStartDate(new ASN1GeneralizedTime("20250101000000Z"));
        gen.setEndDate(new ASN1GeneralizedTime("20260101000000Z"));

        try
        {
            gen.generateAttributeCertificateInfo();
            fail("V2 attr cert generator accepted empty issuer");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    private static DERSequence buildAttrCertInfo(Object issuer)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(ASN1Integer.ONE);                    // version v2
        v.add(holder().toASN1Primitive());        // holder
        v.add((org.bouncycastle.asn1.ASN1Encodable)issuer); // issuer (CHOICE)
        v.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")));
        v.add(ASN1Integer.ONE);                    // serial
        v.add(new AttCertValidityPeriod(
            new ASN1GeneralizedTime("20250101000000Z"),
            new ASN1GeneralizedTime("20260101000000Z")));
        v.add(new DERSequence());                  // attributes (empty seq is OK at parse time)
        return new DERSequence(v);
    }

    private static Holder holder()
    {
        return new Holder(new GeneralNames(new GeneralName(new X500Name(
            new RDN[]{new RDN(org.bouncycastle.asn1.x500.style.BCStyle.CN,
                new org.bouncycastle.asn1.DERUTF8String("Holder"))}))));
    }

    public static void main(String[] args)
    {
        runTest(new AttributeCertificateInfoIssuerTest());
    }
}
