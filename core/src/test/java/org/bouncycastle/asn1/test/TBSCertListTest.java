package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V2TBSCertListGenerator;
import org.bouncycastle.util.test.SimpleTest;

public class TBSCertListTest
    extends SimpleTest
{
    public String getName()
    {
        return "TBSCertList";
    }

    public void performTest()
        throws IOException
    {
        emptyIssuerDNRejected();
        nonEmptyIssuerDNAccepted();
        v2GeneratorRejectsEmptyIssuer();
    }

    private void emptyIssuerDNRejected()
        throws IOException
    {
        // RFC 5280 sec. 5.1.2.3 requires the CRL issuer field to contain a
        // non-empty distinguished name (issue #2010).
        byte[] encoded = buildCRLBody(new X500Name(new RDN[0])).getEncoded(ASN1Encoding.DER);
        try
        {
            TBSCertList.getInstance(encoded);
            fail("empty issuer DN accepted");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("empty distinguished name") >= 0);
        }
    }

    private void nonEmptyIssuerDNAccepted()
        throws IOException
    {
        X500Name issuer = new X500Name(
            new RDN[]{new RDN(BCStyle.CN, new org.bouncycastle.asn1.DERUTF8String("Test CA"))});
        byte[] encoded = buildCRLBody(issuer).getEncoded(ASN1Encoding.DER);

        TBSCertList tbs = TBSCertList.getInstance(encoded);
        if (!tbs.getIssuer().equals(issuer))
        {
            fail("issuer mismatch on roundtrip");
        }
    }

    private static DERSequence buildCRLBody(X500Name issuer)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(1));
        v.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")));
        v.add(issuer);
        v.add(new DERUTCTime("250101000000Z"));
        return new DERSequence(v);
    }

    private void v2GeneratorRejectsEmptyIssuer()
    {
        V2TBSCertListGenerator gen = new V2TBSCertListGenerator();
        gen.setSignature(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11")));
        gen.setIssuer(new X500Name(new RDN[0]));
        gen.setThisUpdate(new Time(new DERUTCTime("250101000000Z")));

        try
        {
            gen.generateTBSCertList();
            fail("V2TBSCertListGenerator accepted empty issuer");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        try
        {
            gen.generatePreTBSCertList();
            fail("V2TBSCertListGenerator pre-tbs accepted empty issuer");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
    {
        runTest(new TBSCertListTest());
    }
}
