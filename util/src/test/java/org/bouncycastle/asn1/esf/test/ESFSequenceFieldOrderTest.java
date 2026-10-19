package org.bouncycastle.asn1.esf.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.esf.CommitmentTypeQualifier;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.esf.SPUserNotice;
import org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The ESF SEQUENCE types take their optional fields at most once, in definition order, and nothing
 * after their last field (github #2516).
 */
public class ESFSequenceFieldOrderTest
    extends SimpleTest
{
    private interface Parser
    {
        Object parse(ASN1Sequence seq);
    }

    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.2.3.4");
    private static final ASN1Integer ONE = new ASN1Integer(1);
    private static final ASN1Encodable EMPTY = new DERSequence();
    private static final ASN1Encodable TEXT = new DERUTF8String("text");

    public String getName()
    {
        return "ESFSequenceFieldOrder";
    }

    private static ASN1Encodable ctx(int tagNo, ASN1Encodable base)
    {
        return new DERTaggedObject(true, tagNo, base);
    }

    private static ASN1Encodable[] els(ASN1Encodable a)
    {
        return new ASN1Encodable[]{ a };
    }

    private static ASN1Encodable[] els(ASN1Encodable a, ASN1Encodable b)
    {
        return new ASN1Encodable[]{ a, b };
    }

    private static ASN1Encodable[] els(ASN1Encodable a, ASN1Encodable b, ASN1Encodable c)
    {
        return new ASN1Encodable[]{ a, b, c };
    }

    // round trip through the encoding so the parser sees tagged objects as they come off the wire
    private static ASN1Sequence wire(ASN1Encodable[] elements)
        throws IOException
    {
        return ASN1Sequence.getInstance(new DERSequence(elements).getEncoded());
    }

    private void accepts(String label, Parser parser, ASN1Encodable[] elements)
        throws IOException
    {
        try
        {
            parser.parse(wire(elements));
        }
        catch (IllegalArgumentException e)
        {
            fail(label + " rejected a valid encoding: " + e.getMessage());
        }
    }

    private void rejects(String label, Parser parser, ASN1Encodable[] elements)
        throws IOException
    {
        try
        {
            parser.parse(wire(elements));
            fail(label + " accepted an invalid encoding");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public void performTest()
        throws Exception
    {
        Parser crlOcspRef = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CrlOcspRef.getInstance(seq);
            }
        };
        // CrlListID and OcspListID are each a SEQUENCE wrapping a SEQUENCE OF
        ASN1Encodable listId = new DERSequence(EMPTY);
        accepts("CrlOcspRef", crlOcspRef, els(ctx(0, listId), ctx(1, listId)));
        rejects("CrlOcspRef duplicate", crlOcspRef, els(ctx(0, listId), ctx(0, listId)));
        rejects("CrlOcspRef order", crlOcspRef, els(ctx(1, listId), ctx(0, listId)));

        Parser revocationValues = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return RevocationValues.getInstance(seq);
            }
        };
        accepts("RevocationValues", revocationValues, els(ctx(0, EMPTY), ctx(1, EMPTY)));
        rejects("RevocationValues duplicate", revocationValues, els(ctx(1, EMPTY), ctx(1, EMPTY)));
        rejects("RevocationValues order", revocationValues, els(ctx(1, EMPTY), ctx(0, EMPTY)));

        Parser signerLocation = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return SignerLocation.getInstance(seq);
            }
        };
        ASN1Encodable country = ctx(0, new DERUTF8String("AU"));
        ASN1Encodable locality = ctx(1, new DERUTF8String("Melbourne"));
        accepts("SignerLocation", signerLocation, els(country, locality));
        rejects("SignerLocation duplicate", signerLocation, els(country, country));
        rejects("SignerLocation order", signerLocation, els(locality, country));

        Parser userNotice = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return SPUserNotice.getInstance(seq);
            }
        };
        ASN1Encodable noticeRef = new DERSequence(els(TEXT, new DERSequence(ONE)));
        accepts("SPUserNotice", userNotice, new ASN1Encodable[0]);
        accepts("SPUserNotice", userNotice, els(noticeRef, TEXT));
        accepts("SPUserNotice", userNotice, els(TEXT));
        rejects("SPUserNotice order", userNotice, els(TEXT, noticeRef));
        rejects("SPUserNotice duplicate", userNotice, els(TEXT, TEXT));

        Parser indication = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CommitmentTypeIndication.getInstance(seq);
            }
        };
        accepts("CommitmentTypeIndication", indication, els(OID, EMPTY));
        rejects("CommitmentTypeIndication trailing element", indication, els(OID, EMPTY, ONE));

        Parser qualifier = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CommitmentTypeQualifier.getInstance(seq);
            }
        };
        accepts("CommitmentTypeQualifier", qualifier, els(OID, ONE));
        rejects("CommitmentTypeQualifier trailing element", qualifier, els(OID, ONE, ONE));

        Parser qualifierInfo = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return SigPolicyQualifierInfo.getInstance(seq);
            }
        };
        accepts("SigPolicyQualifierInfo", qualifierInfo, els(OID, ONE));
        rejects("SigPolicyQualifierInfo trailing element", qualifierInfo, els(OID, ONE, ONE));
        rejects("SigPolicyQualifierInfo missing qualifier", qualifierInfo, els(OID));
    }

    public static void main(String[] args)
    {
        runTest(new ESFSequenceFieldOrderTest());
    }
}
