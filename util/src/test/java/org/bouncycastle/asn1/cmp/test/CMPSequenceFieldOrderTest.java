package org.bouncycastle.asn1.cmp.test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CAKeyUpdAnnContent;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.Challenge;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.KeyRecRepContent;
import org.bouncycastle.asn1.cmp.OOBCertHash;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.cmp.RootCaKeyUpdateContent;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The CMP SEQUENCE types take their optional fields at most once, in definition order and with the
 * right tag, and nothing after their last field (github #2516).
 */
public class CMPSequenceFieldOrderTest
    extends SimpleTest
{
    private interface Parser
    {
        Object parse(ASN1Sequence seq);
    }

    private static final AlgorithmIdentifier SHA256_RSA = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
    private static final AlgorithmIdentifier RSA = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
    private static final ASN1Integer ZERO = new ASN1Integer(0);
    private static final ASN1Integer ONE = new ASN1Integer(1);
    private static final ASN1Encodable OCTETS = new DEROctetString(new byte[8]);
    private static final ASN1Encodable BITS = new DERBitString(new byte[]{ 1 });
    private static final X500Name NAME = new X500Name("CN=Test");
    private static final GeneralName GNAME = new GeneralName(NAME);
    private static final ASN1Encodable STATUS = new DERSequence(ZERO);
    private static final ASN1Encodable FREE_TEXT = new DERSequence(new DERUTF8String("text"));

    public String getName()
    {
        return "CMPSequenceFieldOrder";
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

    private static Certificate certificate()
    {
        V3TBSCertificateGenerator gen = new V3TBSCertificateGenerator();
        gen.setSerialNumber(ONE);
        gen.setSignature(SHA256_RSA);
        gen.setIssuer(NAME);
        gen.setStartDate(new Time(new Date(0)));
        gen.setEndDate(new Time(new Date(1000000000000L)));
        gen.setSubject(NAME);
        gen.setSubjectPublicKeyInfo(new SubjectPublicKeyInfo(RSA, new byte[]{ 0 }));
        return Certificate.getInstance(new DERSequence(els(gen.generateTBSCertificate(), SHA256_RSA, BITS)));
    }

    public void performTest()
        throws Exception
    {
        Certificate cert = certificate();

        pkiHeaderAndMessage();
        certifiedKeyPair(cert);
        certRepMessage(cert);
        oobCertHash();
        rootCaKeyUpdate(cert);
        certStatus();
        keyRecRep(cert);
        revRep();
        challenge();
        errorMsg();
        boundedTypes(cert);
    }

    private static ASN1Encodable[] headerHead()
    {
        return new ASN1Encodable[]{ new ASN1Integer(2), GNAME, GNAME };
    }

    private void pkiHeaderAndMessage()
        throws IOException
    {
        Parser header = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return PKIHeader.getInstance(seq);
            }
        };
        ASN1Encodable time = ctx(0, true, new ASN1GeneralizedTime(new Date(0)));
        ASN1Encodable txId = ctx(4, true, OCTETS);
        accepts("PKIHeader", header, concat(headerHead(), els(time, txId)));
        rejects("PKIHeader duplicate", header, concat(headerHead(), els(txId, txId)));
        rejects("PKIHeader order", header, concat(headerHead(), els(txId, time)));
        rejects("PKIHeader class", header, concat(headerHead(), els(app(4, true, OCTETS))));
        rejects("PKIHeader untagged", header, concat(headerHead(), els(time, ONE)));

        Parser msg = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return PKIMessage.getInstance(seq);
            }
        };
        ASN1Encodable hdr = new DERSequence(headerHead());
        ASN1Encodable body = ctx(19, true, DERNull.INSTANCE);
        ASN1Encodable protection = ctx(0, true, BITS);
        ASN1Encodable extraCerts = ctx(1, true, new DERSequence());
        accepts("PKIMessage", msg, els(hdr, body));
        accepts("PKIMessage", msg, els(hdr, body, protection, extraCerts));
        rejects("PKIMessage duplicate protection", msg, els(hdr, body, protection, ctx(0, true, new DERBitString(new byte[]{ 2 }))));
        rejects("PKIMessage order", msg, els(hdr, body, extraCerts, protection));
        rejects("PKIMessage unknown tag", msg, els(hdr, body, ctx(2, true, new DERSequence())));
    }

    private void certifiedKeyPair(Certificate cert)
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CertifiedKeyPair.getInstance(seq);
            }
        };
        ASN1Encodable certOrEncCert = ctx(0, true, cert);
        ASN1Encodable privateKey = ctx(0, true, new DERSequence(BITS));
        ASN1Encodable pubInfo = ctx(1, true, new DERSequence(ZERO));
        accepts("CertifiedKeyPair", p, els(certOrEncCert));
        accepts("CertifiedKeyPair", p, els(certOrEncCert, privateKey, pubInfo));
        accepts("CertifiedKeyPair", p, els(certOrEncCert, pubInfo));
        rejects("CertifiedKeyPair order", p, els(certOrEncCert, pubInfo, privateKey));
        rejects("CertifiedKeyPair duplicate", p, els(certOrEncCert, pubInfo, pubInfo));
        rejects("CertifiedKeyPair unknown tag", p, els(certOrEncCert, ctx(2, true, new DERSequence(ZERO))));
    }

    private void certRepMessage(Certificate cert)
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CertRepMessage.getInstance(seq);
            }
        };
        ASN1Encodable response = new DERSequence();
        accepts("CertRepMessage", p, els(ctx(1, true, new DERSequence(cert)), response));
        rejects("CertRepMessage [0] as caPubs", p, els(ctx(0, true, new DERSequence(cert)), response));
        rejects("CertRepMessage trailing element", p, els(ctx(1, true, new DERSequence(cert)), response, response));
    }

    private void oobCertHash()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return OOBCertHash.getInstance(seq);
            }
        };
        ASN1Encodable hashAlg = ctx(0, true, RSA);
        ASN1Encodable certId = ctx(1, true, new DERSequence(els(GNAME, ONE)));
        accepts("OOBCertHash", p, els(BITS));
        accepts("OOBCertHash", p, els(hashAlg, certId, BITS));
        rejects("OOBCertHash duplicate", p, els(hashAlg, hashAlg, BITS));
        rejects("OOBCertHash order", p, els(certId, hashAlg, BITS));
        rejects("OOBCertHash trailing element", p, els(hashAlg, BITS, BITS));
    }

    private void rootCaKeyUpdate(Certificate cert)
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return RootCaKeyUpdateContent.getInstance(seq);
            }
        };
        accepts("RootCaKeyUpdateContent", p, els(cert, ctx(0, true, cert), ctx(1, true, cert)));
        rejects("RootCaKeyUpdateContent duplicate", p, els(cert, ctx(1, true, cert), ctx(1, true, cert)));
        rejects("RootCaKeyUpdateContent order", p, els(cert, ctx(1, true, cert), ctx(0, true, cert)));
        rejects("RootCaKeyUpdateContent unknown tag", p, els(cert, ctx(2, true, cert)));
    }

    private void certStatus()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CertStatus.getInstance(seq);
            }
        };
        ASN1Encodable hashAlg = ctx(0, true, RSA);
        accepts("CertStatus", p, els(OCTETS, ZERO));
        accepts("CertStatus", p, els(OCTETS, ZERO, STATUS, hashAlg));
        accepts("CertStatus", p, els(OCTETS, ZERO, hashAlg));
        rejects("CertStatus order", p, els(OCTETS, ZERO, hashAlg, STATUS));
        rejects("CertStatus duplicate statusInfo", p, els(OCTETS, ZERO, STATUS, STATUS));
        rejects("CertStatus untagged trailing", p, els(OCTETS, ZERO, STATUS, ONE));
    }

    private void keyRecRep(Certificate cert)
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return KeyRecRepContent.getInstance(seq);
            }
        };
        ASN1Encodable caCerts = ctx(1, true, new DERSequence(cert));
        accepts("KeyRecRepContent", p, els(STATUS, ctx(0, true, cert), caCerts));
        rejects("KeyRecRepContent duplicate", p, els(STATUS, caCerts, caCerts));
        rejects("KeyRecRepContent order", p, els(STATUS, caCerts, ctx(0, true, cert)));
    }

    private void revRep()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return RevRepContent.getInstance(seq);
            }
        };
        ASN1Encodable status = new DERSequence(STATUS);
        ASN1Encodable revCerts = ctx(0, true, new DERSequence());
        ASN1Encodable crls = ctx(1, true, new DERSequence());
        accepts("RevRepContent", p, els(status, revCerts, crls));
        rejects("RevRepContent duplicate", p, els(status, crls, crls));
        rejects("RevRepContent order", p, els(status, crls, revCerts));
        rejects("RevRepContent unknown tag", p, els(status, ctx(2, true, new DERSequence())));
    }

    private void challenge()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return Challenge.getInstance(seq);
            }
        };
        ASN1Encodable ktri = new DERSequence(new ASN1Encodable[]{ ZERO, new IssuerAndSerialNumber(NAME, BigInteger.ONE), RSA, OCTETS });
        ASN1Encodable eci = new DERSequence(new ASN1Encodable[]{ PKCSObjectIdentifiers.data, RSA });
        ASN1Encodable envelopedData = new DERSequence(els(new ASN1Integer(2), new DERSet(ktri), eci));
        ASN1Encodable empty = new DEROctetString(new byte[0]);
        accepts("Challenge", p, els(OCTETS, OCTETS));
        accepts("Challenge", p, els(OCTETS, empty, ctx(0, true, envelopedData)));
        rejects("Challenge [1] as encryptedRand", p, els(OCTETS, empty, ctx(1, true, envelopedData)));
        rejects("Challenge trailing element", p, els(OCTETS, empty, ctx(0, true, envelopedData), ONE));
    }

    private void errorMsg()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return ErrorMsgContent.getInstance(seq);
            }
        };
        accepts("ErrorMsgContent", p, els(STATUS));
        accepts("ErrorMsgContent", p, els(STATUS, ONE, FREE_TEXT));
        accepts("ErrorMsgContent", p, els(STATUS, FREE_TEXT));
        rejects("ErrorMsgContent order", p, els(STATUS, FREE_TEXT, ONE));
        rejects("ErrorMsgContent duplicate", p, els(STATUS, ONE, ONE));
        rejects("ErrorMsgContent trailing element", p, els(STATUS, ONE, FREE_TEXT, FREE_TEXT));
    }

    private void boundedTypes(Certificate cert)
        throws IOException
    {
        Parser caKeyUpd = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CAKeyUpdAnnContent.getInstance(seq);
            }
        };
        accepts("CAKeyUpdAnnContent", caKeyUpd, els(cert, cert, cert));
        rejects("CAKeyUpdAnnContent trailing element", caKeyUpd, els(cert, cert, cert, cert));

        Parser protectedPart = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return ProtectedPart.getInstance(seq);
            }
        };
        ASN1Encodable hdr = new DERSequence(headerHead());
        ASN1Encodable body = ctx(19, true, DERNull.INSTANCE);
        accepts("ProtectedPart", protectedPart, els(hdr, body));
        rejects("ProtectedPart trailing element", protectedPart, els(hdr, body, ONE));

        Parser pbm = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return PBMParameter.getInstance(seq);
            }
        };
        accepts("PBMParameter", pbm, els(OCTETS, RSA, ONE, RSA));
        rejects("PBMParameter trailing element", pbm, concat(els(OCTETS, RSA, ONE, RSA), els(ONE)));

        Parser pollRep = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return PollRepContent.getInstance(seq);
            }
        };
        accepts("PollRepContent", pollRep, els(new DERSequence(els(ZERO, ONE, FREE_TEXT))));
        rejects("PollRepContent trailing element", pollRep, els(new DERSequence(els(ZERO, ONE, FREE_TEXT, ONE))));

        Parser certResponse = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return CertResponse.getInstance(seq);
            }
        };
        ASN1Encodable ckp = new DERSequence(ctx(0, true, cert));
        accepts("CertResponse", certResponse, els(ZERO, STATUS, ckp, OCTETS));
        rejects("CertResponse trailing element", certResponse, concat(els(ZERO, STATUS, ckp, OCTETS), els(ONE)));

        Parser itv = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return InfoTypeAndValue.getInstance(seq);
            }
        };
        accepts("InfoTypeAndValue", itv, els(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
        rejects("InfoTypeAndValue trailing element", itv, els(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE, ONE));

        Parser statusInfo = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return PKIStatusInfo.getInstance(seq);
            }
        };
        accepts("PKIStatusInfo", statusInfo, els(ZERO, FREE_TEXT, BITS));
        rejects("PKIStatusInfo trailing element", statusInfo, els(ZERO, FREE_TEXT, BITS, ONE));

        Parser revDetails = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return RevDetails.getInstance(seq);
            }
        };
        accepts("RevDetails", revDetails, els(new DERSequence()));
        rejects("RevDetails trailing element", revDetails, els(new DERSequence(), new DERSequence(), ONE));
    }

    public static void main(String[] args)
    {
        runTest(new CMPSequenceFieldOrderTest());
    }
}
