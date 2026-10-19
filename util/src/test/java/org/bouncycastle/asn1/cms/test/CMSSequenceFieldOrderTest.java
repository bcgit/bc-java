package org.bouncycastle.asn1.cms.test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AuthEnvelopedData;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.CompressedData;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.DigestedData;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EncryptedData;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.MetaData;
import org.bouncycastle.asn1.cms.OriginatorInfo;
import org.bouncycastle.asn1.cms.OtherKeyAttribute;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientKeyIdentifier;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.TimeStampAndCRL;
import org.bouncycastle.asn1.cms.TimeStampedData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The CMS SEQUENCE types take their optional tagged fields at most once, in definition order and
 * with the right tag number, and nothing after their last field (github #2516).
 */
public class CMSSequenceFieldOrderTest
    extends SimpleTest
{
    private interface Parser
    {
        Object parse(ASN1Sequence seq);
    }

    private static final AlgorithmIdentifier SHA256 = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"));
    private static final AlgorithmIdentifier RSA = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
    private static final AlgorithmIdentifier AES = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.2"), new DEROctetString(new byte[16]));
    private static final ASN1Integer ZERO = new ASN1Integer(0);
    private static final ASN1Integer ONE = new ASN1Integer(1);
    private static final ASN1Integer TWO = new ASN1Integer(2);
    private static final ASN1Encodable OCTETS = new DEROctetString(new byte[16]);
    private static final ASN1Encodable IAS = new IssuerAndSerialNumber(new X500Name("CN=Test"), BigInteger.ONE);
    private static final ASN1Encodable ATTRS = new DERSet(new Attribute(CMSAttributes.contentType, new DERSet(CMSObjectIdentifiers.data)));
    private static final ASN1Encodable DATA = new ContentInfo(CMSObjectIdentifiers.data, null);
    private static final ASN1Encodable ECI = new DERSequence(new ASN1Encodable[]{ CMSObjectIdentifiers.data, AES });
    private static final ASN1Encodable KTRI = new DERSequence(new ASN1Encodable[]{ ZERO, IAS, RSA, OCTETS });
    private static final ASN1Encodable RECIPIENTS = new DERSet(KTRI);

    public String getName()
    {
        return "CMSSequenceFieldOrder";
    }

    private static ASN1Encodable ctx(int tagNo, boolean explicit, ASN1Encodable base)
    {
        return new DERTaggedObject(explicit, tagNo, base);
    }

    private static ASN1Encodable app(int tagNo, boolean explicit, ASN1Encodable base)
    {
        return new DERTaggedObject(explicit, BERTags.APPLICATION, tagNo, base);
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

    private static ASN1Encodable[] concat(ASN1Encodable[] head, ASN1Encodable[] tail)
    {
        ASN1Encodable[] all = new ASN1Encodable[head.length + tail.length];
        System.arraycopy(head, 0, all, 0, head.length);
        System.arraycopy(tail, 0, all, head.length, tail.length);
        return all;
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
        signedData();
        signerInfo();
        envelopedData();
        authEnvelopedData();
        authenticatedData();
        originatorInfo();
        recipientInfos();
        encryptedContent();
        fixedSizeTypes();
        keyIdentifiers();
        timeStampedData();
    }

    private void signedData()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return SignedData.getInstance(seq);
            }
        };
        ASN1Encodable[] head = new ASN1Encodable[]{ ONE, new DERSet(), DATA };
        ASN1Encodable certs = ctx(0, false, new DERSet());
        ASN1Encodable crls = ctx(1, false, new DERSet());
        ASN1Encodable signerInfos = new DERSet();
        accepts("SignedData", p, concat(head, new ASN1Encodable[]{ signerInfos }));
        accepts("SignedData", p, concat(head, els(certs, crls, signerInfos)));
        rejects("SignedData duplicate certificates", p, concat(head, els(certs, certs, signerInfos)));
        rejects("SignedData order", p, concat(head, els(crls, certs, signerInfos)));
        rejects("SignedData two signerInfos", p, concat(head, els(signerInfos, new DERSet(ONE))));
        rejects("SignedData certificates after signerInfos", p, concat(head, els(signerInfos, certs)));
        rejects("SignedData unknown tag", p, concat(head, els(ctx(2, false, new DERSet()), signerInfos)));
        rejects("SignedData no signerInfos", p, concat(head, new ASN1Encodable[]{ certs }));
    }

    private void signerInfo()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return SignerInfo.getInstance(seq);
            }
        };
        ASN1Encodable[] head = new ASN1Encodable[]{ ONE, IAS, SHA256 };
        accepts("SignerInfo", p, concat(head, els(RSA, OCTETS)));
        accepts("SignerInfo", p, concat(head, els(ctx(0, false, ATTRS), RSA, OCTETS, ctx(1, false, ATTRS))));
        rejects("SignerInfo [1] as signedAttrs", p, concat(head, els(ctx(1, false, ATTRS), RSA, OCTETS)));
        rejects("SignerInfo [0] as unsignedAttrs", p, concat(head, els(RSA, OCTETS, ctx(0, false, ATTRS))));
        rejects("SignerInfo trailing element", p, concat(head, els(RSA, OCTETS, ctx(1, false, ATTRS), ONE)));
        rejects("SignerInfo class", p, concat(head, els(app(0, false, ATTRS), RSA, OCTETS)));
    }

    private void envelopedData()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return EnvelopedData.getInstance(seq);
            }
        };
        ASN1Encodable orig = ctx(0, false, new DERSequence());
        ASN1Encodable unprotected = ctx(1, false, ATTRS);
        accepts("EnvelopedData", p, els(TWO, RECIPIENTS, ECI));
        accepts("EnvelopedData", p, concat(els(TWO, orig, RECIPIENTS), els(ECI, unprotected)));
        rejects("EnvelopedData [1] as originatorInfo", p, els(TWO, ctx(1, false, new DERSequence()), RECIPIENTS, ECI));
        rejects("EnvelopedData [0] as unprotectedAttrs", p, els(TWO, RECIPIENTS, ECI, ctx(0, false, ATTRS)));
        rejects("EnvelopedData trailing element", p, concat(els(TWO, RECIPIENTS, ECI), els(unprotected, ONE)));
    }

    private void authEnvelopedData()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return AuthEnvelopedData.getInstance(seq);
            }
        };
        ASN1Encodable authAttrs = ctx(1, false, ATTRS);
        ASN1Encodable unauthAttrs = ctx(2, false, ATTRS);
        accepts("AuthEnvelopedData", p, els(ZERO, RECIPIENTS, ECI, OCTETS));
        accepts("AuthEnvelopedData", p, concat(els(ZERO, RECIPIENTS, ECI), els(authAttrs, OCTETS, unauthAttrs)));
        rejects("AuthEnvelopedData [2] as authAttrs", p, concat(els(ZERO, RECIPIENTS, ECI), els(unauthAttrs, OCTETS)));
        rejects("AuthEnvelopedData [1] as unauthAttrs", p, concat(els(ZERO, RECIPIENTS, ECI), els(OCTETS, authAttrs)));
        rejects("AuthEnvelopedData trailing element", p, concat(els(ZERO, RECIPIENTS, ECI), els(OCTETS, unauthAttrs, ONE)));
    }

    private void authenticatedData()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return AuthenticatedData.getInstance(seq);
            }
        };
        ASN1Encodable[] head = new ASN1Encodable[]{ ZERO, RECIPIENTS, SHA256 };
        ASN1Encodable digAlg = ctx(1, false, SHA256);
        ASN1Encodable authAttrs = ctx(2, false, ATTRS);
        ASN1Encodable unauthAttrs = ctx(3, false, ATTRS);
        accepts("AuthenticatedData", p, concat(head, els(DATA, OCTETS)));
        accepts("AuthenticatedData", p, concat(head, concat(els(digAlg, DATA, authAttrs), els(OCTETS, unauthAttrs))));
        rejects("AuthenticatedData [2] as digestAlgorithm", p, concat(head, concat(els(ctx(2, false, SHA256), DATA, authAttrs), new ASN1Encodable[]{ OCTETS })));
        rejects("AuthenticatedData [3] as authAttrs", p, concat(head, concat(els(digAlg, DATA, ctx(3, false, ATTRS)), new ASN1Encodable[]{ OCTETS })));
        rejects("AuthenticatedData trailing element", p, concat(head, els(DATA, OCTETS, unauthAttrs, ONE)));
    }

    private void originatorInfo()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return OriginatorInfo.getInstance(seq);
            }
        };
        ASN1Encodable certs = ctx(0, false, new DERSet());
        ASN1Encodable crls = ctx(1, false, new DERSet());
        accepts("OriginatorInfo", p, els(certs, crls));
        accepts("OriginatorInfo", p, new ASN1Encodable[]{ crls });
        rejects("OriginatorInfo order", p, els(crls, certs));
        rejects("OriginatorInfo duplicate", p, els(certs, certs));
        rejects("OriginatorInfo class", p, new ASN1Encodable[]{ app(0, false, new DERSet()) });
    }

    private void recipientInfos()
        throws IOException
    {
        Parser ktri = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return KeyTransRecipientInfo.getInstance(seq);
            }
        };
        accepts("KeyTransRecipientInfo", ktri, els(ZERO, IAS, RSA, OCTETS));
        rejects("KeyTransRecipientInfo trailing element", ktri, concat(els(ZERO, IAS, RSA, OCTETS), new ASN1Encodable[]{ ONE }));

        Parser kari = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return KeyAgreeRecipientInfo.getInstance(seq);
            }
        };
        ASN1Encodable originator = ctx(0, true, IAS);
        ASN1Encodable ukm = ctx(1, true, OCTETS);
        ASN1Encodable keys = new DERSequence(new DERSequence(new ASN1Encodable[]{ IAS, OCTETS }));
        accepts("KeyAgreeRecipientInfo", kari, els(TWO, originator, RSA, keys));
        accepts("KeyAgreeRecipientInfo", kari, concat(els(TWO, originator, ukm), els(RSA, keys)));
        rejects("KeyAgreeRecipientInfo [1] as originator", kari, els(TWO, ctx(1, true, IAS), RSA, keys));
        rejects("KeyAgreeRecipientInfo [0] as ukm", kari, concat(els(TWO, originator, ctx(0, true, OCTETS)), els(RSA, keys)));
        rejects("KeyAgreeRecipientInfo trailing element", kari, concat(els(TWO, originator, RSA), els(keys, ONE)));

        Parser kekri = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return KEKRecipientInfo.getInstance(seq);
            }
        };
        ASN1Encodable kekid = new DERSequence(OCTETS);
        accepts("KEKRecipientInfo", kekri, els(new ASN1Integer(4), kekid, AES, OCTETS));
        rejects("KEKRecipientInfo trailing element", kekri, concat(els(new ASN1Integer(4), kekid, AES, OCTETS), new ASN1Encodable[]{ ONE }));

        Parser pwri = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return PasswordRecipientInfo.getInstance(seq);
            }
        };
        ASN1Encodable kdf = ctx(0, false, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2));
        accepts("PasswordRecipientInfo", pwri, els(ZERO, AES, OCTETS));
        accepts("PasswordRecipientInfo", pwri, els(ZERO, kdf, AES, OCTETS));
        rejects("PasswordRecipientInfo [1] as keyDerivationAlgorithm", pwri, els(ZERO, ctx(1, false, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2)), AES, OCTETS));
        rejects("PasswordRecipientInfo trailing element", pwri, els(ZERO, AES, OCTETS, ONE));
        rejects("PasswordRecipientInfo trailing element after kdf", pwri, concat(els(ZERO, kdf, AES, OCTETS), new ASN1Encodable[]{ ONE }));
    }

    private void encryptedContent()
        throws IOException
    {
        Parser eci = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return EncryptedContentInfo.getInstance(seq);
            }
        };
        accepts("EncryptedContentInfo", eci, els(CMSObjectIdentifiers.data, AES, ctx(0, false, OCTETS)));
        rejects("EncryptedContentInfo [1] as encryptedContent", eci, els(CMSObjectIdentifiers.data, AES, ctx(1, false, OCTETS)));
        rejects("EncryptedContentInfo trailing element", eci, els(CMSObjectIdentifiers.data, AES, ctx(0, false, OCTETS), ONE));

        Parser ed = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return EncryptedData.getInstance(seq);
            }
        };
        accepts("EncryptedData", ed, els(TWO, ECI, ctx(1, false, ATTRS)));
        rejects("EncryptedData [0] as unprotectedAttrs", ed, els(TWO, ECI, ctx(0, false, ATTRS)));
        rejects("EncryptedData trailing element", ed, els(TWO, ECI, ctx(1, false, ATTRS), ONE));
    }

    private void fixedSizeTypes()
        throws IOException
    {
        Parser cd = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CompressedData.getInstance(seq);
            }
        };
        AlgorithmIdentifier zlib = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.8"));
        accepts("CompressedData", cd, els(ZERO, zlib, DATA));
        rejects("CompressedData trailing element", cd, els(ZERO, zlib, DATA, ONE));

        Parser dd = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return DigestedData.getInstance(seq);
            }
        };
        accepts("DigestedData", dd, els(ZERO, SHA256, DATA, OCTETS));
        rejects("DigestedData trailing element", dd, concat(els(ZERO, SHA256, DATA, OCTETS), new ASN1Encodable[]{ ONE }));

        Parser oka = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return OtherKeyAttribute.getInstance(seq);
            }
        };
        accepts("OtherKeyAttribute", oka, els(CMSObjectIdentifiers.data, ONE));
        rejects("OtherKeyAttribute trailing element", oka, els(CMSObjectIdentifiers.data, ONE, ONE));
    }

    private void keyIdentifiers()
        throws IOException
    {
        Parser rki = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return RecipientKeyIdentifier.getInstance(seq);
            }
        };
        ASN1Encodable other = new DERSequence(new ASN1Encodable[]{ CMSObjectIdentifiers.data, ONE });
        accepts("RecipientKeyIdentifier", rki, els(OCTETS, new ASN1GeneralizedTime(new Date(0))));
        // subjectKeyIdentifier and other with no date was read from the wrong index
        accepts("RecipientKeyIdentifier without date", rki, els(OCTETS, other));
        RecipientKeyIdentifier parsed = RecipientKeyIdentifier.getInstance(wire(els(OCTETS, other)));
        isTrue("RecipientKeyIdentifier other", parsed.getOtherKeyAttribute() != null && parsed.getDate() == null);
    }

    private void timeStampedData()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return TimeStampedData.getInstance(seq);
            }
        };
        ASN1Encodable evidence = ctx(0, false, new DERSequence(new TimeStampAndCRL(new ContentInfo(CMSObjectIdentifiers.signedData, null))));
        ASN1Encodable metaData = new MetaData(ASN1Boolean.TRUE, new DERUTF8String("f.txt"), new DERIA5String("text/plain"), null);
        accepts("TimeStampedData", p, els(ONE, new DERIA5String("https://a.example/"), metaData, evidence));
        rejects("TimeStampedData trailing element", p, els(ONE, metaData, evidence, ONE));

        Parser md = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return MetaData.getInstance(seq);
            }
        };
        accepts("MetaData", md, els(ASN1Boolean.TRUE, new DERUTF8String("f.txt")));
        rejects("MetaData trailing element", md, els(ASN1Boolean.TRUE, new DERUTF8String("f.txt"), new DERBitString(new byte[1])));
    }

    public static void main(String[] args)
    {
        runTest(new CMSSequenceFieldOrderTest());
    }
}
