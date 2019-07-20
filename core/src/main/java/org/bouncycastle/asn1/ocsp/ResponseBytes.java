package org.bouncycastle.asn1.ocsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * OCSP RFC 2560, RFC 6960
 * <pre>
 * ResponseBytes ::=       SEQUENCE {
 *     responseType   OBJECT IDENTIFIER,
 *     response       OCTET STRING }
 * </pre>
 */
public class ResponseBytes
    extends ASN1Object
{
    ASN1ObjectIdentifier    responseType;
    ASN1OctetString        response;

    public ResponseBytes(
        ASN1ObjectIdentifier responseType,
        ASN1OctetString     response)
    {
        this.responseType = responseType;
        this.response = response;
    }

    /**
     * @deprecated use getInstance()
     */
    public ResponseBytes(
        ASN1Sequence    seq)
    {
        responseType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        response = (ASN1OctetString)seq.getObjectAt(1);
    }

    public static ResponseBytes getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ResponseBytes getInstance(
        Object  obj)
    {
        if (obj instanceof ResponseBytes)
        {
            return (ResponseBytes)obj;
        }
        else if (obj != null)
        {
            return new ResponseBytes(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1ObjectIdentifier getResponseType()
    {
        return responseType;
    }

    public ASN1OctetString getResponse()
    {
        return response;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * ResponseBytes ::=       SEQUENCE {
     *     responseType   OBJECT IDENTIFIER,
     *     response       OCTET STRING }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(responseType);
        v.add(response);

        return new DERSequence(v);
    }
}
