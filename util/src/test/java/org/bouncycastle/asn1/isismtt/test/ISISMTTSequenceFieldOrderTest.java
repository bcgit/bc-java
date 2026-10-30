package org.bouncycastle.asn1.isismtt.test;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
import org.bouncycastle.asn1.isismtt.x509.ProcurationSyntax;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The ISIS-MTT SEQUENCE types take their optional fields at most once and in definition order,
 * and nothing after their last field (github #2516).
 */
public class ISISMTTSequenceFieldOrderTest
    extends SimpleTest
{
    private interface Parser
    {
        Object parse(ASN1Sequence seq);
    }

    private static final ASN1Encodable ONE = new ASN1Integer(1);
    private static final ASN1Encodable OID = new ASN1ObjectIdentifier("1.2.3.4");
    private static final ASN1Encodable URL = new DERIA5String("http://example.com");
    private static final ASN1Encodable TEXT = new DERUTF8String("text");
    private static final ASN1Encodable ITEMS = new DERSequence(new DERUTF8String("item"));
    private static final ASN1Encodable OIDS = new DERSequence(OID);
    private static final ASN1Encodable REG_NO = new DERPrintableString("123");
    private static final ASN1Encodable ADD_INFO = new DEROctetString(new byte[]{ 1 });

    public String getName()
    {
        return "ISISMTTSequenceFieldOrder";
    }

    private static ASN1Encodable ctx(int tagNo, boolean explicit, ASN1Encodable base)
    {
        return new DERTaggedObject(explicit, tagNo, base);
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

    private static ASN1Encodable[] els(ASN1Encodable a, ASN1Encodable b, ASN1Encodable c, ASN1Encodable d)
    {
        return new ASN1Encodable[]{ a, b, c, d };
    }

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
        namingAuthority();
        professionInfo();
        procurationSyntax();
    }

    private void namingAuthority()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return NamingAuthority.getInstance(seq);
            }
        };
        accepts("NamingAuthority", p, new ASN1Encodable[0]);
        accepts("NamingAuthority", p, els(OID, URL, TEXT));
        accepts("NamingAuthority", p, els(URL));
        accepts("NamingAuthority", p, els(OID, TEXT));
        rejects("NamingAuthority text before url", p, els(TEXT, URL));
        rejects("NamingAuthority url twice", p, els(URL, new DERIA5String("http://y")));
        rejects("NamingAuthority oid after url", p, els(URL, OID));
        rejects("NamingAuthority trailing", p, els(OID, URL, TEXT, ONE));
    }

    private void professionInfo()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return ProfessionInfo.getInstance(seq);
            }
        };
        ASN1Encodable namingAuthority = ctx(0, true, new DERSequence(OID));

        accepts("ProfessionInfo", p, els(ITEMS));
        accepts("ProfessionInfo", p, els(namingAuthority, ITEMS, OIDS, REG_NO));
        accepts("ProfessionInfo", p, els(ITEMS, ADD_INFO));
        rejects("ProfessionInfo [5] namingAuthority", p, els(ctx(5, true, new DERSequence(OID)), ITEMS));
        rejects("ProfessionInfo addProfessionInfo before registrationNumber", p, els(ITEMS, ADD_INFO, REG_NO));
        rejects("ProfessionInfo addProfessionInfo twice", p, els(ITEMS, ADD_INFO, new DEROctetString(new byte[]{ 2 })));
        rejects("ProfessionInfo trailing", p, new ASN1Encodable[]{ ITEMS, OIDS, REG_NO, ADD_INFO, ONE });
    }

    private void procurationSyntax()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return ProcurationSyntax.getInstance(seq);
            }
        };
        ASN1Encodable country = ctx(1, true, new DERPrintableString("AU"));
        ASN1Encodable type = ctx(2, true, TEXT);
        ASN1Encodable thirdPerson = ctx(3, true, new GeneralNames(new GeneralName(new X500Name("CN=Third"))).getNames()[0]);
        ASN1Encodable certRef = ctx(3, true, new IssuerSerial(new GeneralNames(new GeneralName(new X500Name("CN=Issuer"))), BigInteger.ONE));

        accepts("ProcurationSyntax", p, els(thirdPerson));
        accepts("ProcurationSyntax", p, els(country, type, certRef));
        accepts("ProcurationSyntax", p, els(type, thirdPerson));
        rejects("ProcurationSyntax country twice", p, els(country, country, thirdPerson));
        rejects("ProcurationSyntax order", p, els(thirdPerson, country));
        rejects("ProcurationSyntax signingFor missing", p, els(country));
        rejects("ProcurationSyntax unknown tag", p, els(ctx(5, true, TEXT), thirdPerson));
    }

    public static void main(String[] args)
    {
        runTest(new ISISMTTSequenceFieldOrderTest());
    }
}
