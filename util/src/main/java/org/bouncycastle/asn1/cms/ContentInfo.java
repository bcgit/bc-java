package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-3">RFC 5652</a> ContentInfo, and
 * <a href="https://tools.ietf.org/html/rfc5652#section-5.2">RFC 5652</a> EncapsulatedContentInfo objects.
 *
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *     contentType ContentType,
 *     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 *
 * EncapsulatedContentInfo ::= SEQUENCE {
 *     eContentType ContentType,
 *     eContent [0] EXPLICIT OCTET STRING OPTIONAL
 * }
 * </pre>
 */
public class ContentInfo
    extends ASN1Object
    implements CMSObjectIdentifiers
{
    private final ASN1ObjectIdentifier contentType;
    private final ASN1Encodable        content;
    private final boolean              isDefiniteLength;

    /**
     * Return an ContentInfo object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link ContentInfo} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with ContentInfo structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static ContentInfo getInstance(
        Object  obj)
    {
        if (obj instanceof ContentInfo)
        {
            return (ContentInfo)obj;
        }
        else if (obj != null)
        {
            return new ContentInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static ContentInfo getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    private ContentInfo(
        ASN1Sequence  seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        contentType = (ASN1ObjectIdentifier)seq.getObjectAt(0);

        if (seq.size() > 1)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(1), BERTags.CONTEXT_SPECIFIC);
            if (!tagged.isExplicit() || tagged.getTagNo() != 0)
            {
                throw new IllegalArgumentException("Bad tag for 'content'");
            }

            content = tagged.getExplicitBaseObject();
        }
        else
        {
            content = null;
        }
        isDefiniteLength = !(seq instanceof BERSequence);
    }

    public ContentInfo(
        ASN1ObjectIdentifier contentType,
        ASN1Encodable        content)
    {
        this.contentType = contentType;
        this.content = content;
        if (content != null)
        {
            ASN1Primitive prim = content.toASN1Primitive();
            this.isDefiniteLength =
                prim instanceof DEROctetString
                    || prim instanceof DLSequence
                    || prim instanceof DERSequence;
        }
        else
        {
            // no content, keep it simple.
            this.isDefiniteLength = true;
        }
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    public ASN1Encodable getContent()
    {
        return content;
    }

    /**
     * Return true if this object encapsulates a definite-length structure.
     *
     * @return true if definite-length, false if indefinite.
     */
    public boolean isDefiniteLength()
    {
        return isDefiniteLength;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector(2);

        v.add(contentType);

        if (content != null)
        {
            if (isDefiniteLength)
            {
                v.add(new DLTaggedObject(0, content));
            }
            else
            {
                v.add(new BERTaggedObject(0, content));
            }
        }

        return isDefiniteLength ? (ASN1Primitive)new DLSequence(v) : (ASN1Primitive)new BERSequence(v);
    }
}
