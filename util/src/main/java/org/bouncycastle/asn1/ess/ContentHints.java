package org.bouncycastle.asn1.ess;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class ContentHints
    extends ASN1Object
{
    private ASN1UTF8String contentDescription;
    private ASN1ObjectIdentifier contentType;

    public static ContentHints getInstance(Object o)
    {
        if (o instanceof ContentHints)
        {
            return (ContentHints)o;
        }
        else if (o != null)
        {
            return new ContentHints(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * constructor
     */
    private ContentHints(ASN1Sequence seq)
    {
        ASN1Encodable field = seq.getObjectAt(0);
        if (field.toASN1Primitive() instanceof ASN1UTF8String)
        {
            contentDescription = ASN1UTF8String.getInstance(field);
            contentType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
        }
        else
        {
            contentType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        }
    }

    public ContentHints(
        ASN1ObjectIdentifier contentType)
    {
        this.contentType = contentType;
        this.contentDescription = null;
    }

    public ContentHints(
        ASN1ObjectIdentifier contentType,
        ASN1UTF8String contentDescription)
    {
        this.contentType = contentType;
        this.contentDescription = contentDescription;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    /**
     * @deprecated Use {@link #getContentDescriptionUTF8()} instead.
     */
    public DERUTF8String getContentDescription()
    {
        return null == contentDescription || contentDescription instanceof DERUTF8String
            ?   (DERUTF8String)contentDescription
            :   new DERUTF8String(contentDescription.getString());
    }

    public ASN1UTF8String getContentDescriptionUTF8()
    {
        return contentDescription;
    }

    /**
     * <pre>
     * ContentHints ::= SEQUENCE {
     *   contentDescription UTF8String (SIZE (1..MAX)) OPTIONAL,
     *   contentType ContentType }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        if (contentDescription != null)
        {
            v.add(contentDescription);
        }

        v.add(contentType);

        return new DERSequence(v);
    }
}
