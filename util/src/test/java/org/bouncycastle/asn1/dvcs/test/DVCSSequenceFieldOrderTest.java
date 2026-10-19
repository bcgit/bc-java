package org.bouncycastle.asn1.dvcs.test;

import java.io.IOException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.dvcs.DVCSCertInfo;
import org.bouncycastle.asn1.dvcs.DVCSErrorNotice;
import org.bouncycastle.asn1.dvcs.DVCSRequest;
import org.bouncycastle.asn1.dvcs.DVCSRequestInformation;
import org.bouncycastle.asn1.dvcs.PathProcInput;
import org.bouncycastle.asn1.dvcs.TargetEtcChain;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The DVCS SEQUENCE types take their optional fields at most once, in definition order and with the
 * right tag, and nothing after their last field (github #2516).
 */
public class DVCSSequenceFieldOrderTest
    extends SimpleTest
{
    private interface Parser
    {
        Object parse(ASN1Sequence seq);
    }

    private static final ASN1Integer ONE = new ASN1Integer(1);
    private static final ASN1Encodable SERVICE = new ASN1Enumerated(1);
    private static final ASN1Encodable TIME = new ASN1GeneralizedTime(new Date(0));
    private static final GeneralName NAME = new GeneralName(new X500Name("CN=Test"));
    private static final ASN1Encodable STATUS = new DERSequence(new ASN1Integer(0));
    private static final Extension EXTENSION = new Extension(new ASN1ObjectIdentifier("1.2.3.4"), false, new byte[]{ 5, 0 });

    public String getName()
    {
        return "DVCSSequenceFieldOrder";
    }

    private static ASN1Encodable ctx(int tagNo, ASN1Encodable base)
    {
        return new DERTaggedObject(false, tagNo, base);
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
        ASN1Encodable names = new GeneralNames(NAME);
        ASN1Encodable exts = new Extensions(EXTENSION);

        Parser reqInfo = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return DVCSRequestInformation.getInstance(seq);
            }
        };
        ASN1Encodable requester = ctx(0, names);
        ASN1Encodable dvcs = ctx(2, names);
        accepts("DVCSRequestInformation", reqInfo, els(SERVICE));
        accepts("DVCSRequestInformation", reqInfo, concat(els(SERVICE, ONE, TIME), els(requester, dvcs)));
        rejects("DVCSRequestInformation time before nonce", reqInfo, els(SERVICE, TIME, ONE));
        rejects("DVCSRequestInformation two nonces", reqInfo, els(SERVICE, ONE, ONE));
        rejects("DVCSRequestInformation duplicate", reqInfo, els(SERVICE, requester, requester));
        rejects("DVCSRequestInformation order", reqInfo, els(SERVICE, dvcs, requester));

        Parser certInfo = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return DVCSCertInfo.getInstance(seq);
            }
        };
        ASN1Encodable imprint = new DERSequence(els(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), new DEROctetString(new byte[32])));
        ASN1Encodable[] head = new ASN1Encodable[]{ new DERSequence(SERVICE), imprint, ONE, TIME };
        ASN1Encodable dvStatus = ctx(0, STATUS);
        ASN1Encodable certs = ctx(3, new DERSequence(new DERSequence(EXTENSION)));
        accepts("DVCSCertInfo", certInfo, head);
        accepts("DVCSCertInfo", certInfo, concat(head, els(dvStatus, certs, exts)));
        rejects("DVCSCertInfo duplicate", certInfo, concat(head, els(dvStatus, dvStatus)));
        rejects("DVCSCertInfo order", certInfo, concat(head, els(certs, dvStatus)));
        rejects("DVCSCertInfo tag after extensions", certInfo, concat(head, els(exts, dvStatus)));
        rejects("DVCSCertInfo junk where extensions belong", certInfo, concat(head, els(ONE)));

        Parser path = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return PathProcInput.getInstance(seq);
            }
        };
        ASN1Encodable policies = new DERSequence();
        ASN1Encodable explicit = ctx(0, ASN1Boolean.TRUE);
        ASN1Encodable inhibitAny = ctx(1, ASN1Boolean.TRUE);
        accepts("PathProcInput", path, els(policies, ASN1Boolean.TRUE, explicit, inhibitAny));
        rejects("PathProcInput order", path, els(policies, inhibitAny, explicit));
        rejects("PathProcInput duplicate", path, els(policies, explicit, explicit));
        rejects("PathProcInput unexpected type", path, els(policies, ONE));

        Parser chain = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return TargetEtcChain.getInstance(seq);
            }
        };
        ASN1Encodable target = EXTENSION;
        ASN1Encodable pathProc = ctx(0, new DERSequence(policies));
        accepts("TargetEtcChain", chain, els(target, new DERSequence(target), pathProc));
        accepts("TargetEtcChain", chain, els(target, pathProc));
        rejects("TargetEtcChain element after pathProcInput", chain, els(target, pathProc, new DERSequence(target)));
        rejects("TargetEtcChain trailing element", chain, concat(els(target, new DERSequence(target), pathProc), els(ONE)));

        Parser request = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return DVCSRequest.getInstance(seq);
            }
        };
        ASN1Encodable info = new DERSequence(SERVICE);
        ASN1Encodable data = new DEROctetString(new byte[4]);
        accepts("DVCSRequest", request, els(info, data, NAME));
        rejects("DVCSRequest trailing element", request, els(info, data, NAME, ONE));

        Parser notice = new Parser()
        {
            public Object parse(ASN1Sequence seq)
            {
                return DVCSErrorNotice.getInstance(seq);
            }
        };
        accepts("DVCSErrorNotice", notice, els(STATUS, NAME));
        rejects("DVCSErrorNotice trailing element", notice, els(STATUS, NAME, ONE));
    }

    public static void main(String[] args)
    {
        runTest(new DVCSSequenceFieldOrderTest());
    }
}
