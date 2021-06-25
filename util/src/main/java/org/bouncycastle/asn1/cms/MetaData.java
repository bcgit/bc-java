package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * <a href="https://tools.ietf.org/html/rfc5544">RFC 5544</a>:
 * Binding Documents with Time-Stamps; MetaData object.
 * <p>
 * <pre>
 * MetaData ::= SEQUENCE {
 *   hashProtected        BOOLEAN,
 *   fileName             UTF8String OPTIONAL,
 *   mediaType            IA5String OPTIONAL,
 *   otherMetaData        Attributes OPTIONAL
 * }
 * </pre>
 */
public class MetaData
    extends ASN1Object
{
    private ASN1Boolean hashProtected;
    private ASN1UTF8String fileName;
    private ASN1IA5String  mediaType;
    private Attributes otherMetaData;

    public MetaData(
        ASN1Boolean hashProtected,
        ASN1UTF8String fileName,
        ASN1IA5String mediaType,
        Attributes otherMetaData)
    {
        this.hashProtected = hashProtected;
        this.fileName = fileName;
        this.mediaType = mediaType;
        this.otherMetaData = otherMetaData;
    }

    private MetaData(ASN1Sequence seq)
    {
        this.hashProtected = ASN1Boolean.getInstance(seq.getObjectAt(0));

        int index = 1;

        if (index < seq.size() && seq.getObjectAt(index) instanceof ASN1UTF8String)
        {
            this.fileName = ASN1UTF8String.getInstance(seq.getObjectAt(index++));
        }
        if (index < seq.size() && seq.getObjectAt(index) instanceof ASN1IA5String)
        {
            this.mediaType = ASN1IA5String.getInstance(seq.getObjectAt(index++));
        }
        if (index < seq.size())
        {
            this.otherMetaData = Attributes.getInstance(seq.getObjectAt(index++));
        }
    }

    /**
     * Return a MetaData object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link MetaData} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with MetaData structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static MetaData getInstance(Object obj)
    {
        if (obj instanceof MetaData)
        {
            return (MetaData)obj;
        }
        else if (obj != null)
        {
            return new MetaData(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(hashProtected);

        if (fileName != null)
        {
            v.add(fileName);
        }

        if (mediaType != null)
        {
            v.add(mediaType);
        }

        if (otherMetaData != null)
        {
            v.add(otherMetaData);
        }
        
        return new DERSequence(v);
    }

    public boolean isHashProtected()
    {
        return hashProtected.isTrue();
    }

    /**
     * @deprecated Use {@link #getFileNameUTF8()} instead.
     */
    public DERUTF8String getFileName()
    {
        return null == fileName || fileName instanceof DERUTF8String
            ?   (DERUTF8String)fileName
            :   new DERUTF8String(fileName.getString());
    }

    public ASN1UTF8String getFileNameUTF8()
    {
        return this.fileName;
    }

    /**
     * @deprecated Use {@link #getMediaTypeIA5()} instead.
     */
    public DERIA5String getMediaType()
    {
        return null == mediaType || mediaType instanceof DERIA5String
            ?   (DERIA5String)mediaType
            :   new DERIA5String(mediaType.getString(), false);
    }

    public ASN1IA5String getMediaTypeIA5()
    {
        return this.mediaType;
    }

    public Attributes getOtherMetaData()
    {
        return otherMetaData;
    }
}
