package org.bouncycastle.asn1.crmf.test;

import java.io.IOException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.EncKeyWithID;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.PKIPublicationInfo;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.SinglePubInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The CRMF SEQUENCE types take their optional tagged fields at most once, in definition order and
 * with the right tag, and nothing after their last field (github #2516).
 */
public class CRMFSequenceFieldOrderTest
    extends SimpleTest
{
    private interface Parser
    {
        Object parse(ASN1Sequence seq);
    }

    private static final AlgorithmIdentifier RSA = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
    private static final ASN1Integer ZERO = new ASN1Integer(0);
    private static final ASN1Integer ONE = new ASN1Integer(1);
    private static final ASN1Encodable BITS = new DERBitString(new byte[]{ 1 });
    private static final GeneralName NAME = new GeneralName(new X500Name("CN=Test"));

    public String getName()
    {
        return "CRMFSequenceFieldOrder";
    }

    private static ASN1Encodable ctx(int tagNo, boolean explicit, ASN1Encodable base)
    {
        return new DERTaggedObject(explicit, tagNo, base);
    }

    private static ASN1Encodable app(int tagNo, boolean explicit, ASN1Encodable base)
    {
        return new DERTaggedObject(explicit, BERTags.APPLICATION, tagNo, base);
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
        certTemplate();
        optionalValidity();
        encryptedValue();
        certRequestAndMsg();
        popoSigningKey();
        fixedSizeTypes();
    }

    private void certTemplate()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CertTemplate.getInstance(seq);
            }
        };
        ASN1Encodable serial = ctx(1, false, ONE);
        ASN1Encodable subject = ctx(5, true, new X500Name("CN=Subject"));
        accepts("CertTemplate", p, new ASN1Encodable[0]);
        accepts("CertTemplate", p, els(ctx(0, false, new ASN1Integer(2)), serial, subject));
        rejects("CertTemplate duplicate", p, els(serial, ctx(1, false, new ASN1Integer(2))));
        rejects("CertTemplate order", p, els(subject, serial));
        rejects("CertTemplate class", p, els(app(1, false, ONE)));
        rejects("CertTemplate untagged", p, els(serial, ONE));
    }

    private void optionalValidity()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return OptionalValidity.getInstance(seq);
            }
        };
        ASN1Encodable notBefore = ctx(0, true, new Time(new Date(0)));
        ASN1Encodable notAfter = ctx(1, true, new Time(new Date(1000000000000L)));
        accepts("OptionalValidity", p, els(notBefore, notAfter));
        rejects("OptionalValidity duplicate", p, els(notAfter, notAfter));
        rejects("OptionalValidity order", p, els(notAfter, notBefore));
        rejects("OptionalValidity unknown tag", p, els(ctx(2, true, new Time(new Date(0)))));
    }

    private void encryptedValue()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return EncryptedValue.getInstance(seq);
            }
        };
        ASN1Encodable symmAlg = ctx(1, false, RSA);
        ASN1Encodable hint = ctx(4, false, new DEROctetString(new byte[1]));
        accepts("EncryptedValue", p, els(BITS));
        accepts("EncryptedValue", p, els(symmAlg, hint, BITS));
        rejects("EncryptedValue duplicate", p, els(symmAlg, symmAlg, BITS));
        rejects("EncryptedValue order", p, els(hint, symmAlg, BITS));
        rejects("EncryptedValue trailing element", p, els(symmAlg, BITS, ONE));
        rejects("EncryptedValue no encValue", p, els(symmAlg));
    }

    private void certRequestAndMsg()
        throws IOException
    {
        Parser req = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CertRequest.getInstance(seq);
            }
        };
        ASN1Encodable template = new DERSequence();
        ASN1Encodable controls = new DERSequence(new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String("t")));
        accepts("CertRequest", req, els(ZERO, template, controls));
        rejects("CertRequest trailing element", req, els(ZERO, template, controls, ONE));

        Parser msg = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CertReqMsg.getInstance(seq);
            }
        };
        ASN1Encodable certReq = new DERSequence(els(ZERO, template));
        ASN1Encodable raVerified = ctx(0, false, DERNull.INSTANCE);
        ASN1Encodable regInfo = new DERSequence();
        accepts("CertReqMsg", msg, els(certReq));
        accepts("CertReqMsg", msg, els(certReq, raVerified, regInfo));
        accepts("CertReqMsg", msg, els(certReq, regInfo));
        rejects("CertReqMsg duplicate popo", msg, els(certReq, raVerified, raVerified));
        rejects("CertReqMsg order", msg, els(certReq, regInfo, raVerified));
        rejects("CertReqMsg duplicate regInfo", msg, els(certReq, regInfo, regInfo));
    }

    private void popoSigningKey()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return POPOSigningKey.getInstance(seq);
            }
        };
        accepts("POPOSigningKey", p, els(RSA, BITS));
        rejects("POPOSigningKey trailing element", p, els(RSA, BITS, ONE));
    }

    private void fixedSizeTypes()
        throws IOException
    {
        Parser certId = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CertId.getInstance(seq);
            }
        };
        accepts("CertId", certId, els(NAME, ONE));
        rejects("CertId trailing element", certId, els(NAME, ONE, ONE));

        Parser pkmac = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return PKMACValue.getInstance(seq);
            }
        };
        accepts("PKMACValue", pkmac, els(RSA, BITS));
        rejects("PKMACValue trailing element", pkmac, els(RSA, BITS, ONE));

        Parser atv = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return AttributeTypeAndValue.getInstance(seq);
            }
        };
        accepts("AttributeTypeAndValue", atv, els(CRMFObjectIdentifiers.id_regCtrl_regToken, ONE));
        rejects("AttributeTypeAndValue trailing element", atv, els(CRMFObjectIdentifiers.id_regCtrl_regToken, ONE, ONE));

        Parser pubInfo = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return PKIPublicationInfo.getInstance(seq);
            }
        };
        accepts("PKIPublicationInfo", pubInfo, els(ZERO));
        rejects("PKIPublicationInfo trailing element", pubInfo, els(ZERO, new DERSequence(), ONE));

        Parser single = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return SinglePubInfo.getInstance(seq);
            }
        };
        accepts("SinglePubInfo", single, els(ZERO, NAME));
        rejects("SinglePubInfo trailing element", single, els(ZERO, NAME, ONE));

        Parser encKey = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return EncKeyWithID.getInstance(seq);
            }
        };
        ASN1Encodable pki = new PrivateKeyInfo(RSA, new DEROctetString(new byte[1]));
        accepts("EncKeyWithID", encKey, els(pki, new DERUTF8String("id")));
        rejects("EncKeyWithID trailing element", encKey, els(pki, new DERUTF8String("id"), ONE));
    }

    public static void main(String[] args)
    {
        runTest(new CRMFSequenceFieldOrderTest());
    }
}
