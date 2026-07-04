package org.bouncycastle.asn1.cms.test;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.test.SimpleTest;

public class SignerInfoTest
    extends SimpleTest
{
    private static final AlgorithmIdentifier digAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"));
    private static final AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"));

    public String getName()
    {
        return "SignerInfo";
    }

    private static Attributes attrs(ASN1ObjectIdentifier type, ASN1ObjectIdentifier value)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new Attribute(type, new DERSet(value)));
        return new Attributes(v);
    }

    public void performTest()
        throws Exception
    {
        SignerIdentifier sid = new SignerIdentifier(
            new IssuerAndSerialNumber(new X500Name("CN=Test"), new BigInteger("42")));

        SignerInfo si = new SignerInfo(sid, digAlg,
            attrs(CMSAttributes.contentType, new ASN1ObjectIdentifier("1.2.3")),
            sigAlg, new DEROctetString(new byte[]{ 9, 9, 9 }),
            attrs(CMSAttributes.counterSignature, new ASN1ObjectIdentifier("1.2.4")));

        byte[] enc = si.getEncoded(ASN1Encoding.DER);
        SignerInfo back = SignerInfo.getInstance(ASN1Primitive.fromByteArray(enc));
        if (!areEqual(enc, back.getEncoded(ASN1Encoding.DER)))
        {
            fail("well-formed SignerInfo did not round-trip");
        }

        // SignerInfo.getInstance must reject a structurally-valid SEQUENCE whose version element is
        // not an INTEGER (here an OBJECT IDENTIFIER) with IllegalArgumentException, rather than leak
        // a ClassCastException from a (ASN1Integer) cast out of the getInstance contract.
        ASN1EncodableVector badVersion = new ASN1EncodableVector();
        badVersion.add(new ASN1ObjectIdentifier("1.2.3.4"));
        badVersion.add(new DEROctetString(new byte[]{ 1 }));
        badVersion.add(digAlg);
        badVersion.add(sigAlg);
        badVersion.add(new DEROctetString(new byte[]{ 2 }));
        try
        {
            SignerInfo.getInstance(new DERSequence(badVersion));
            fail("SignerInfo.getInstance accepted a non-INTEGER version element");
        }
        catch (IllegalArgumentException e)
        {
            // expected - documented malformed reject
        }

        // The unsignedAttrs slot must likewise reject a non-tagged trailing element with
        // IllegalArgumentException rather than a leaked (ASN1TaggedObject) ClassCastException.
        ASN1EncodableVector badUnsigned = new ASN1EncodableVector();
        badUnsigned.add(new ASN1Integer(1));
        badUnsigned.add(new DEROctetString(new byte[]{ 1 }));
        badUnsigned.add(digAlg);
        badUnsigned.add(sigAlg);
        badUnsigned.add(new DEROctetString(new byte[]{ 2 }));
        badUnsigned.add(new ASN1Integer(99));
        try
        {
            SignerInfo.getInstance(new DERSequence(badUnsigned));
            fail("SignerInfo.getInstance accepted a non-tagged unsignedAttrs element");
        }
        catch (IllegalArgumentException e)
        {
            // expected - documented malformed reject
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new SignerInfoTest());
    }
}
