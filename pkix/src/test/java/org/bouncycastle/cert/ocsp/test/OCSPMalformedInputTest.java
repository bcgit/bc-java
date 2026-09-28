package org.bouncycastle.cert.ocsp.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLBitString;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.util.test.SimpleTest;

/**
 * A malformed encoding handed to the OCSPResp(byte[]) / OCSPReq(byte[]) parsers must be reported
 * through the declared IOException, not as an unchecked exception. A top-level SEQUENCE that is
 * empty or truncated makes OCSPResponse/OCSPRequest read seq.getObjectAt(0) out of bounds, and the
 * parsers only caught IllegalArgumentException/ClassCastException/ASN1Exception, so the
 * ArrayIndexOutOfBoundsException escaped the throws IOException contract (same shape already
 * handled by X509CertificateHolder / X509CRLHolder).
 */
public class OCSPMalformedInputTest
    extends SimpleTest
{
    public String getName()
    {
        return "OCSPMalformedInputTest";
    }

    public void performTest()
        throws Exception
    {
        // empty SEQUENCE, one-element SEQUENCE holding a truncated inner SEQUENCE, and a
        // non-SEQUENCE top-level element.
        byte[][] malformed = new byte[][]
        {
            new byte[]{ 0x30, 0x00 },
            new byte[]{ 0x30, 0x03, 0x30, 0x01, 0x00 },
            new byte[]{ 0x02, 0x01, 0x00 },
        };

        for (int i = 0; i != malformed.length; i++)
        {
            checkResp(malformed[i]);
            checkReq(malformed[i]);
        }

        // well-formed input still parses without change.
        byte[] validResp = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, null).getEncoded();
        new OCSPResp(validResp);

        byte[] validReq = new OCSPReqBuilder().build().getEncoded();
        new OCSPReq(validReq);

        checkASN1();
    }

    /**
     * The ASN.1 types themselves read fixed positions of their SEQUENCE, so a short one has to be
     * refused with the IllegalArgumentException getInstance() documents, rather than an
     * ArrayIndexOutOfBoundsException - they are also parsed directly, by the provider's OCSP
     * revocation checker and by TLS among others. ResponseData and TBSRequest open with an optional
     * version, so their required fields have to be counted after it.
     */
    private void checkASN1()
    {
        ASN1Sequence empty = new DERSequence();
        ASN1Encodable version = new DERTaggedObject(true, 0, new ASN1Integer(0));
        ASN1Encodable responderID = new ResponderID(new X500Name("CN=Responder"));
        ASN1Encodable producedAt = new ASN1GeneralizedTime("20260101000000Z");

        checkRejected("OCSPResponse", new ASN1Op() { public Object go(ASN1Sequence seq) { return OCSPResponse.getInstance(seq); } }, empty);
        checkRejected("OCSPRequest", new ASN1Op() { public Object go(ASN1Sequence seq) { return OCSPRequest.getInstance(seq); } }, empty);
        checkRejected("Request", new ASN1Op() { public Object go(ASN1Sequence seq) { return Request.getInstance(seq); } }, empty);

        ASN1Op basic = new ASN1Op() { public Object go(ASN1Sequence seq) { return BasicOCSPResponse.getInstance(seq); } };
        checkRejected("BasicOCSPResponse", basic, empty);
        checkRejected("BasicOCSPResponse", basic, new DERSequence(new ASN1Encodable[]{ empty, empty }));

        ASN1Op responseData = new ASN1Op() { public Object go(ASN1Sequence seq) { return ResponseData.getInstance(seq); } };
        checkRejected("ResponseData", responseData, empty);
        checkRejected("ResponseData", responseData, new DERSequence(new ASN1Encodable[]{ responderID, producedAt }));
        // a version, so the three fields that follow it are two short
        checkRejected("ResponseData", responseData, new DERSequence(new ASN1Encodable[]{ version, responderID, producedAt }));

        ASN1Op tbsRequest = new ASN1Op() { public Object go(ASN1Sequence seq) { return TBSRequest.getInstance(seq); } };
        checkRejected("TBSRequest", tbsRequest, empty);
        checkRejected("TBSRequest", tbsRequest, new DERSequence(version));
        // a version and a requestorName, but no requestList after them
        checkRejected("TBSRequest", tbsRequest, new DERSequence(new ASN1Encodable[]{ version,
            new DERTaggedObject(true, 1, new org.bouncycastle.asn1.x509.GeneralName(new X500Name("CN=Requestor"))) }));

        checkWrongTypes(responderID, producedAt);
        checkLenientBitString(responderID, producedAt);
    }

    /**
     * An element of the wrong type was cast rather than passed to getInstance(), so it surfaced as a
     * ClassCastException. The optional trailing fields were cast to ASN1TaggedObject on the strength
     * of there being another element at all.
     */
    private void checkWrongTypes(ASN1Encodable responderID, ASN1Encodable producedAt)
    {
        ASN1Encodable nul = DERNull.INSTANCE;
        ASN1Encodable octets = new DEROctetString(new byte[20]);
        ASN1Encodable algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"));
        ASN1Sequence responseData = new DERSequence(new ASN1Encodable[]{ responderID, producedAt, new DERSequence() });
        ASN1Encodable certID = new DERSequence(new ASN1Encodable[]{ algId, octets, octets, new ASN1Integer(1) });

        checkRejected("CertID", new ASN1Op() { public Object go(ASN1Sequence seq) { return CertID.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ algId, nul, octets, new ASN1Integer(1) }));
        checkRejected("CertID", new ASN1Op() { public Object go(ASN1Sequence seq) { return CertID.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ algId, octets, octets, nul }));
        checkRejected("ResponseBytes", new ASN1Op() { public Object go(ASN1Sequence seq) { return ResponseBytes.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ nul, octets }));
        checkRejected("ResponseBytes", new ASN1Op() { public Object go(ASN1Sequence seq) { return ResponseBytes.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.1"), nul }));
        checkRejected("BasicOCSPResponse", new ASN1Op() { public Object go(ASN1Sequence seq) { return BasicOCSPResponse.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ responseData, algId, nul }));
        checkRejected("BasicOCSPResponse", new ASN1Op() { public Object go(ASN1Sequence seq) { return BasicOCSPResponse.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ responseData, algId, new DERBitString(new byte[1]), nul }));
        checkRejected("ResponseData", new ASN1Op() { public Object go(ASN1Sequence seq) { return ResponseData.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ responderID, producedAt, nul }));
        checkRejected("ResponseData", new ASN1Op() { public Object go(ASN1Sequence seq) { return ResponseData.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ responderID, producedAt, new DERSequence(), nul }));
        checkRejected("TBSRequest", new ASN1Op() { public Object go(ASN1Sequence seq) { return TBSRequest.getInstance(seq); } },
            new DERSequence(nul));
        checkRejected("TBSRequest", new ASN1Op() { public Object go(ASN1Sequence seq) { return TBSRequest.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ new DERSequence(), nul }));
        checkRejected("OCSPResponse", new ASN1Op() { public Object go(ASN1Sequence seq) { return OCSPResponse.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ new org.bouncycastle.asn1.ASN1Enumerated(0), nul }));
        checkRejected("OCSPRequest", new ASN1Op() { public Object go(ASN1Sequence seq) { return OCSPRequest.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ new DERSequence(new DERSequence()), nul }));
        checkRejected("Request", new ASN1Op() { public Object go(ASN1Sequence seq) { return Request.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ certID, nul }));
        checkRejected("RevokedInfo", new ASN1Op() { public Object go(ASN1Sequence seq) { return RevokedInfo.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ producedAt, nul }));
        ASN1Encodable good = new DERTaggedObject(false, 0, DERNull.INSTANCE);
        checkRejected("SingleResponse", new ASN1Op() { public Object go(ASN1Sequence seq) { return SingleResponse.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ certID, good, producedAt, nul }));
        checkRejected("SingleResponse", new ASN1Op() { public Object go(ASN1Sequence seq) { return SingleResponse.getInstance(seq); } },
            new DERSequence(new ASN1Encodable[]{ certID, good, producedAt, nul, nul }));
    }

    /**
     * The signature BIT STRING was cast to DERBitString, so one that had arrived in another legal
     * encoding - DL or BER, as a parser yields for input that is not DER - was refused outright.
     */
    private void checkLenientBitString(ASN1Encodable responderID, ASN1Encodable producedAt)
    {
        ASN1Encodable algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"));
        ASN1Sequence responseData = new DERSequence(new ASN1Encodable[]{ responderID, producedAt, new DERSequence() });
        byte[] sig = new byte[]{ 1, 2, 3, 4 };

        BasicOCSPResponse basic = BasicOCSPResponse.getInstance(new DERSequence(new ASN1Encodable[]{ responseData, algId, new DLBitString(sig) }));
        isTrue("BasicOCSPResponse signature lost", org.bouncycastle.util.Arrays.areEqual(sig, basic.getSignature().getOctets()));

        org.bouncycastle.asn1.ocsp.Signature signature = org.bouncycastle.asn1.ocsp.Signature.getInstance(
            new DERSequence(new ASN1Encodable[]{ algId, new DLBitString(sig) }));
        isTrue("Signature signature lost", org.bouncycastle.util.Arrays.areEqual(sig, signature.getSignature().getOctets()));
    }

    private interface ASN1Op
    {
        Object go(ASN1Sequence seq);
    }

    private void checkRejected(String type, ASN1Op op, ASN1Sequence seq)
    {
        try
        {
            op.go(seq);
            fail(type + " accepted a SEQUENCE of " + seq.size());
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        catch (RuntimeException e)
        {
            fail(type + " threw " + e.getClass().getName() + " for a SEQUENCE of " + seq.size(), e);
        }
    }

    private void checkResp(byte[] encoding)
    {
        boolean reported = false;
        try
        {
            new OCSPResp(encoding);
        }
        catch (IOException e)
        {
            reported = true;
        }
        catch (Exception e)
        {
            fail("OCSPResp threw " + e.getClass().getName() + " rather than IOException", e);
        }

        if (!reported)
        {
            fail("malformed OCSP response accepted");
        }
    }

    private void checkReq(byte[] encoding)
    {
        boolean reported = false;
        try
        {
            new OCSPReq(encoding);
        }
        catch (IOException e)
        {
            reported = true;
        }
        catch (Exception e)
        {
            fail("OCSPReq threw " + e.getClass().getName() + " rather than IOException", e);
        }

        if (!reported)
        {
            fail("malformed OCSP request accepted");
        }
    }

    public static void main(String[] args)
    {
        runTest(new OCSPMalformedInputTest());
    }
}
