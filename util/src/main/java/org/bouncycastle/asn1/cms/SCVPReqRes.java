package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <a href="https://tools.ietf.org/html/rfc5940">RFC 5940</a>:
 * Additional Cryptographic Message Syntax (CMS) Revocation Information Choices.
 * <p>
 * <pre>
 * SCVPReqRes ::= SEQUENCE {
 *     request  [0] EXPLICIT ContentInfo OPTIONAL,
 *     response     ContentInfo }
 * </pre>
 */
public class SCVPReqRes
    extends ASN1Object
{
    private final ContentInfo request;
    private final ContentInfo response;

    /**
     * Return a SCVPReqRes object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link SCVPReqRes} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with SCVPReqRes structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static SCVPReqRes getInstance(Object obj)
    {
        if (obj instanceof SCVPReqRes)
        {
            return (SCVPReqRes)obj;
        }
        else if (obj != null)
        {
            return new SCVPReqRes(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static SCVPReqRes getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new SCVPReqRes(ASN1Sequence.getInstance(taggedObject, declaredExplicit));
    }

    public static SCVPReqRes getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new SCVPReqRes(ASN1Sequence.getTagged(taggedObject, declaredExplicit));
    }

    private SCVPReqRes(ASN1Sequence seq)
    {
        int count = seq.size(), pos = 0;
        if (count < 1 || count > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + count);
        }

        // request [0] EXPLICIT ContentInfo OPTIONAL
        ContentInfo request = null;
        if (pos < count)
        {
            ASN1TaggedObject tag0 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 0);
            if (tag0 != null)
            {
                pos++;
                request = ContentInfo.getTagged(tag0, true);
            }
        }
        this.request = request;

        this.response = ContentInfo.getInstance(seq.getObjectAt(pos++));

        if (pos != count)
        {
            throw new IllegalArgumentException("Unexpected elements in sequence");
        }
    }

    public SCVPReqRes(ContentInfo response)
    {
        this(null, response);
    }

    public SCVPReqRes(ContentInfo request, ContentInfo response)
    {
        if (response == null)
        {
            throw new NullPointerException("'response' cannot be null");
        }

        this.request = request;
        this.response = response;
    }

    public ContentInfo getRequest()
    {
        return request;
    }

    public ContentInfo getResponse()
    {
        return response;
    }

    /**
     * @return  the ASN.1 primitive representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        if (request == null)
        {
            return new DERSequence(response);
        }

        return new DERSequence(new DERTaggedObject(true, 0, request), response);
    }
}
