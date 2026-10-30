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
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AuthEnvelopedDataParser;
import org.bouncycastle.asn1.cms.AuthenticatedDataParser;
import org.bouncycastle.asn1.cms.AuthEnvelopedData;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.CompressedData;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.EncryptedContentInfoParser;
import org.bouncycastle.asn1.cms.EnvelopedDataParser;
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
import org.bouncycastle.asn1.cms.OriginatorPublicKey;
import org.bouncycastle.asn1.cms.OtherKeyAttribute;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientKeyIdentifier;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignedDataParser;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.TimeStampAndCRL;
import org.bouncycastle.asn1.cms.TimeStampedData;
import org.bouncycastle.asn1.cms.ecc.ECCCMSSharedInfo;
import org.bouncycastle.asn1.cms.ecc.MQVuserKeyingMaterial;
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
        eccSharedInfoAndMqv();
        streamingParsers();
    }

    private void eccSharedInfoAndMqv()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return ECCCMSSharedInfo.getInstance(seq);
            }
        };
        ASN1Encodable ukm = ctx(0, true, OCTETS);
        ASN1Encodable suppPubInfo = ctx(2, true, new DEROctetString(new byte[4]));

        accepts("ECCCMSSharedInfo", p, els(AES, suppPubInfo));
        accepts("ECCCMSSharedInfo entityUInfo", p, els(AES, ukm, suppPubInfo));
        rejects("ECCCMSSharedInfo [5] entityUInfo", p, els(AES, ctx(5, true, OCTETS), suppPubInfo));
        rejects("ECCCMSSharedInfo [5] suppPubInfo", p, els(AES, ctx(5, true, new DEROctetString(new byte[4]))));
        rejects("ECCCMSSharedInfo order", p, els(AES, suppPubInfo, ukm));
        rejects("ECCCMSSharedInfo trailing", p, els(AES, suppPubInfo, ONE));

        p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return MQVuserKeyingMaterial.getInstance(seq);
            }
        };
        ASN1Encodable ephemeralKey = new OriginatorPublicKey(RSA, new byte[]{ 1 });

        accepts("MQVuserKeyingMaterial", p, new ASN1Encodable[]{ ephemeralKey });
        accepts("MQVuserKeyingMaterial addedukm", p, els(ephemeralKey, ukm));
        rejects("MQVuserKeyingMaterial [5] addedukm", p, els(ephemeralKey, ctx(5, true, OCTETS)));
    }

    private interface StreamParser
    {
        void parse(ASN1SequenceParser seq)
            throws IOException;
    }

    private static ASN1SequenceParser stream(ASN1Encodable[] elements)
        throws IOException
    {
        return (ASN1SequenceParser)new ASN1StreamParser(new DERSequence(elements).getEncoded(ASN1Encoding.DER)).readObject();
    }

    private static void drain(ASN1SetParser set)
        throws IOException
    {
        if (set != null)
        {
            ASN1Encodable o;
            while ((o = set.readObject()) != null)
            {
                // a streamed element has to be consumed before the next one can be read
                o.toASN1Primitive();
            }
        }
    }

    private void acceptsStream(String label, StreamParser parser, ASN1Encodable[] elements)
        throws IOException
    {
        try
        {
            parser.parse(stream(elements));
        }
        catch (IOException e)
        {
            fail(label + " rejected a valid encoding: " + e.getMessage());
        }
        catch (IllegalStateException e)
        {
            fail(label + " rejected a valid encoding: " + e.getMessage());
        }
    }

    private void rejectsStream(String label, StreamParser parser, ASN1Encodable[] elements)
        throws IOException
    {
        try
        {
            parser.parse(stream(elements));
            fail(label + " accepted an invalid encoding");
        }
        catch (IOException e)
        {
            // expected
        }
        catch (IllegalStateException e)
        {
            // expected: ASN1ParsingException from the ASN.1 layer
        }
        catch (IllegalArgumentException e)
        {
            // expected: a tag check in the ASN.1 layer
        }
    }

    private void streamingParsers()
        throws IOException
    {
        final ASN1Encodable[] signerInfos = new ASN1Encodable[]{ new DERSet() };
        StreamParser signed = new StreamParser()
        {
            public void parse(ASN1SequenceParser seq)
                throws IOException
            {
                SignedDataParser p = SignedDataParser.getInstance(seq);
                drain(p.getDigestAlgorithms());
                p.getEncapContentInfo().getContent(BERTags.OCTET_STRING);
                drain(p.getCertificates());
                drain(p.getCrls());
                drain(p.getSignerInfos());
            }
        };
        ASN1Encodable[] signedHead = new ASN1Encodable[]{ ONE, new DERSet(), DATA };
        acceptsStream("SignedDataParser", signed, concat(signedHead, signerInfos));
        rejectsStream("SignedDataParser trailing", signed, concat(signedHead, els(new DERSet(), ONE)));
        rejectsStream("SignedDataParser INTEGER signerInfos", signed, concat(signedHead, new ASN1Encodable[]{ ONE }));

        // the same, loading the set rather than streaming it
        StreamParser signedLoaded = new StreamParser()
        {
            public void parse(ASN1SequenceParser seq)
                throws IOException
            {
                SignedDataParser p = SignedDataParser.getInstance(seq);
                drain(p.getDigestAlgorithms());
                p.getEncapContentInfo().getContent(BERTags.OCTET_STRING);
                drain(p.getCertificates());
                drain(p.getCrls());
                p.getSignerInfos().toASN1Primitive();
            }
        };
        acceptsStream("SignedDataParser loaded", signedLoaded, concat(signedHead, signerInfos));
        rejectsStream("SignedDataParser loaded trailing", signedLoaded, concat(signedHead, els(new DERSet(), ONE)));

        StreamParser enveloped = new StreamParser()
        {
            public void parse(ASN1SequenceParser seq)
                throws IOException
            {
                EnvelopedDataParser p = new EnvelopedDataParser(seq);
                p.getOriginatorInfo();
                drain(p.getRecipientInfos());
                p.getEncryptedContentInfo().getEncryptedContent(BERTags.OCTET_STRING);
                drain(p.getUnprotectedAttrs());
            }
        };
        ASN1Encodable[] envelopedHead = new ASN1Encodable[]{ ZERO, RECIPIENTS, ECI };
        ASN1Encodable unprotectedAttrs = ctx(1, false, ATTRS);
        acceptsStream("EnvelopedDataParser", enveloped, envelopedHead);
        acceptsStream("EnvelopedDataParser unprotectedAttrs", enveloped, concat(envelopedHead, new ASN1Encodable[]{ unprotectedAttrs }));
        rejectsStream("EnvelopedDataParser trailing", enveloped, concat(envelopedHead, els(unprotectedAttrs, ONE)));
        rejectsStream("EnvelopedDataParser INTEGER after encryptedContentInfo", enveloped, concat(envelopedHead, new ASN1Encodable[]{ ONE }));
        rejectsStream("EnvelopedDataParser [5] unprotectedAttrs", enveloped, concat(envelopedHead, new ASN1Encodable[]{ ctx(5, false, ATTRS) }));

        StreamParser authEnveloped = new StreamParser()
        {
            public void parse(ASN1SequenceParser seq)
                throws IOException
            {
                AuthEnvelopedDataParser p = new AuthEnvelopedDataParser(seq);
                p.getOriginatorInfo();
                drain(p.getRecipientInfos());
                p.getAuthEncryptedContentInfo().getEncryptedContent(BERTags.OCTET_STRING);
                drain(p.getAuthAttrs());
                p.getMac();
                drain(p.getUnauthAttrs());
            }
        };
        ASN1Encodable[] authEnvelopedHead = new ASN1Encodable[]{ ZERO, RECIPIENTS, ECI, OCTETS };
        ASN1Encodable unauthAttrs2 = ctx(2, false, ATTRS);
        acceptsStream("AuthEnvelopedDataParser", authEnveloped, authEnvelopedHead);
        acceptsStream("AuthEnvelopedDataParser unauthAttrs", authEnveloped, concat(authEnvelopedHead, new ASN1Encodable[]{ unauthAttrs2 }));
        rejectsStream("AuthEnvelopedDataParser trailing", authEnveloped, concat(authEnvelopedHead, els(unauthAttrs2, ONE)));
        rejectsStream("AuthEnvelopedDataParser INTEGER after mac", authEnveloped, concat(authEnvelopedHead, new ASN1Encodable[]{ ONE }));

        StreamParser authenticated = new StreamParser()
        {
            public void parse(ASN1SequenceParser seq)
                throws IOException
            {
                AuthenticatedDataParser p = new AuthenticatedDataParser(seq);
                p.getOriginatorInfo();
                drain(p.getRecipientInfos());
                p.getMacAlgorithm();
                p.getDigestAlgorithm();
                p.getEncapsulatedContentInfo().getContent(BERTags.OCTET_STRING);
                drain(p.getAuthAttrs());
                p.getMac();
                drain(p.getUnauthAttrs());
            }
        };
        ASN1Encodable[] authenticatedHead = new ASN1Encodable[]{ ZERO, RECIPIENTS, RSA };
        ASN1Encodable[] authenticatedTail = new ASN1Encodable[]{ DATA, OCTETS };
        ASN1Encodable unauthAttrs3 = ctx(3, false, ATTRS);
        acceptsStream("AuthenticatedDataParser", authenticated, concat(authenticatedHead, authenticatedTail));
        acceptsStream("AuthenticatedDataParser digestAlgorithm", authenticated, concat(authenticatedHead, concat(new ASN1Encodable[]{ ctx(1, false, SHA256) }, authenticatedTail)));
        acceptsStream("AuthenticatedDataParser unauthAttrs", authenticated, concat(authenticatedHead, concat(authenticatedTail, new ASN1Encodable[]{ unauthAttrs3 })));
        rejectsStream("AuthenticatedDataParser [5] digestAlgorithm", authenticated, concat(authenticatedHead, concat(new ASN1Encodable[]{ ctx(5, false, SHA256) }, authenticatedTail)));
        rejectsStream("AuthenticatedDataParser trailing", authenticated, concat(authenticatedHead, concat(authenticatedTail, els(unauthAttrs3, ONE))));
        rejectsStream("AuthenticatedDataParser INTEGER after mac", authenticated, concat(authenticatedHead, concat(authenticatedTail, new ASN1Encodable[]{ ONE })));

        StreamParser contentInfo = new StreamParser()
        {
            public void parse(ASN1SequenceParser seq)
                throws IOException
            {
                new ContentInfoParser(seq).getContent(BERTags.OCTET_STRING);
            }
        };
        acceptsStream("ContentInfoParser", contentInfo, new ASN1Encodable[]{ CMSObjectIdentifiers.data });
        acceptsStream("ContentInfoParser content", contentInfo, els(CMSObjectIdentifiers.data, ctx(0, true, OCTETS)));
        rejectsStream("ContentInfoParser [5] content", contentInfo, els(CMSObjectIdentifiers.data, ctx(5, true, OCTETS)));
        rejectsStream("ContentInfoParser INTEGER content", contentInfo, els(CMSObjectIdentifiers.data, ONE));

        StreamParser encryptedContentInfo = new StreamParser()
        {
            public void parse(ASN1SequenceParser seq)
                throws IOException
            {
                new EncryptedContentInfoParser(seq).getEncryptedContent(BERTags.OCTET_STRING);
            }
        };
        acceptsStream("EncryptedContentInfoParser", encryptedContentInfo, els(CMSObjectIdentifiers.data, AES));
        acceptsStream("EncryptedContentInfoParser content", encryptedContentInfo, els(CMSObjectIdentifiers.data, AES, ctx(0, false, OCTETS)));
        rejectsStream("EncryptedContentInfoParser [5] content", encryptedContentInfo, els(CMSObjectIdentifiers.data, AES, ctx(5, false, OCTETS)));
        rejectsStream("EncryptedContentInfoParser INTEGER content", encryptedContentInfo, els(CMSObjectIdentifiers.data, AES, ONE));
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
