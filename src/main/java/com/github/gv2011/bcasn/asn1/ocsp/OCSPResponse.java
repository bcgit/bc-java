package com.github.gv2011.bcasn.asn1.ocsp;

import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.ASN1TaggedObject;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.asn1.DERTaggedObject;

public class OCSPResponse
    extends ASN1Object
{
    OCSPResponseStatus    responseStatus;
    ResponseBytes        responseBytes;

    public OCSPResponse(
        OCSPResponseStatus  responseStatus,
        ResponseBytes       responseBytes)
    {
        this.responseStatus = responseStatus;
        this.responseBytes = responseBytes;
    }

    private OCSPResponse(
        ASN1Sequence    seq)
    {
        responseStatus = OCSPResponseStatus.getInstance(seq.getObjectAt(0));

        if (seq.size() == 2)
        {
            responseBytes = ResponseBytes.getInstance(
                                (ASN1TaggedObject)seq.getObjectAt(1), true);
        }
    }

    public static OCSPResponse getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OCSPResponse getInstance(
        Object  obj)
    {
        if (obj instanceof OCSPResponse)
        {
            return (OCSPResponse)obj;
        }
        else if (obj != null)
        {
            return new OCSPResponse(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public OCSPResponseStatus getResponseStatus()
    {
        return responseStatus;
    }

    public ResponseBytes getResponseBytes()
    {
        return responseBytes;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * OCSPResponse ::= SEQUENCE {
     *     responseStatus         OCSPResponseStatus,
     *     responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector    v = new ASN1EncodableVector();

        v.add(responseStatus);

        if (responseBytes != null)
        {
            v.add(new DERTaggedObject(true, 0, responseBytes));
        }

        return new DERSequence(v);
    }
}
