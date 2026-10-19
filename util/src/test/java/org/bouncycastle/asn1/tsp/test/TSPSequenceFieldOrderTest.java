package org.bouncycastle.asn1.tsp.test;

import java.io.IOException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.tsp.TimeStampReq;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The TSP SEQUENCE types take their optional fields at most once, in definition order and with the
 * right tag, and nothing after their last field (github #2516).
 */
public class TSPSequenceFieldOrderTest
    extends SimpleTest
{
    private interface Parser
    {
        Object parse(ASN1Sequence seq);
    }

    private static final AlgorithmIdentifier SHA256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    private static final ASN1ObjectIdentifier POLICY = new ASN1ObjectIdentifier("1.2.3.4");
    private static final ASN1Integer ONE = new ASN1Integer(1);
    private static final ASN1Encodable IMPRINT = new DERSequence(new ASN1Encodable[]{ SHA256, new DEROctetString(new byte[32]) });
    private static final ASN1Encodable EXTENSIONS = new Extensions(new Extension(new ASN1ObjectIdentifier("1.2.3.5"), false, new byte[]{ 5, 0 }));

    public String getName()
    {
        return "TSPSequenceFieldOrder";
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
        tstInfo();
        timeStampReq();
        timeStampResp();
        evidenceRecord();
    }

    private void tstInfo()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return TSTInfo.getInstance(seq);
            }
        };
        ASN1Encodable[] head = new ASN1Encodable[]{ ONE, POLICY, IMPRINT, ONE, new ASN1GeneralizedTime(new Date(0)) };
        ASN1Encodable accuracy = new DERSequence(ONE);
        ASN1Encodable nonce = new ASN1Integer(7);
        ASN1Encodable tsa = ctx(0, true, new GeneralName(new X500Name("CN=TSA")));
        ASN1Encodable exts = ctx(1, false, EXTENSIONS);
        accepts("TSTInfo", p, head);
        accepts("TSTInfo", p, concat(head, concat(els(accuracy, ASN1Boolean.TRUE, nonce), els(tsa, exts))));
        accepts("TSTInfo", p, concat(head, els(nonce, tsa)));
        rejects("TSTInfo two nonces", p, concat(head, els(nonce, new ASN1Integer(8))));
        rejects("TSTInfo two accuracies", p, concat(head, els(accuracy, accuracy)));
        rejects("TSTInfo nonce before ordering", p, concat(head, els(nonce, ASN1Boolean.TRUE)));
        rejects("TSTInfo extensions before tsa", p, concat(head, els(exts, tsa)));
        rejects("TSTInfo unexpected type", p, concat(head, els(new DERUTF8String("x"))));
        rejects("TSTInfo unknown tag", p, concat(head, els(ctx(2, false, EXTENSIONS))));
    }

    private void timeStampReq()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return TimeStampReq.getInstance(seq);
            }
        };
        ASN1Encodable[] head = new ASN1Encodable[]{ ONE, IMPRINT };
        ASN1Encodable nonce = new ASN1Integer(7);
        ASN1Encodable exts = ctx(0, false, EXTENSIONS);
        accepts("TimeStampReq", p, head);
        accepts("TimeStampReq", p, concat(head, concat(els(POLICY, nonce, ASN1Boolean.TRUE), els(exts))));
        rejects("TimeStampReq certReq before nonce", p, concat(head, els(ASN1Boolean.TRUE, nonce)));
        rejects("TimeStampReq two nonces", p, concat(head, els(nonce, nonce)));
        rejects("TimeStampReq unknown tag", p, concat(head, els(ctx(1, false, EXTENSIONS))));
        rejects("TimeStampReq trailing element", p, concat(head, els(nonce, exts, ONE)));
    }

    private void timeStampResp()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return TimeStampResp.getInstance(seq);
            }
        };
        ASN1Encodable status = new DERSequence(new ASN1Integer(0));
        ASN1Encodable token = new ContentInfo(CMSObjectIdentifiers.signedData, DERNull.INSTANCE);
        accepts("TimeStampResp", p, els(status, token));
        rejects("TimeStampResp trailing element", p, els(status, token, token));
    }

    private void evidenceRecord()
        throws IOException
    {
        Parser p = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return EvidenceRecord.getInstance(seq);
            }
        };
        ASN1Encodable digestAlgorithms = new DERSequence(SHA256);
        ASN1Encodable cryptoInfos = ctx(0, false, new DERSequence());
        ASN1Encodable encryptionInfo = ctx(1, false, new DERSequence(new ASN1Encodable[]{ POLICY, ONE }));
        ASN1Encodable atss = new DERSequence();
        accepts("EvidenceRecord", p, concat(els(ONE, digestAlgorithms, cryptoInfos), els(encryptionInfo, atss)));
        rejects("EvidenceRecord duplicate", p, concat(els(ONE, digestAlgorithms, cryptoInfos), els(cryptoInfos, atss)));
        rejects("EvidenceRecord order", p, concat(els(ONE, digestAlgorithms, encryptionInfo), els(cryptoInfos, atss)));
    }

    public static void main(String[] args)
    {
        runTest(new TSPSequenceFieldOrderTest());
    }
}
