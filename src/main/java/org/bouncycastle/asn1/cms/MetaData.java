package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class MetaData
    extends ASN1Object
{
    private ASN1Boolean hashProtected;
    private DERUTF8String fileName;
    private DERIA5String  mediaType;
    private Attributes otherMetaData;

    public MetaData(
        ASN1Boolean hashProtected,
        DERUTF8String fileName,
        DERIA5String mediaType,
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

        if (index < seq.size() && seq.getObjectAt(index) instanceof DERUTF8String)
        {
            this.fileName = DERUTF8String.getInstance(seq.getObjectAt(index++));
        }
        if (index < seq.size() && seq.getObjectAt(index) instanceof DERIA5String)
        {
            this.mediaType = DERIA5String.getInstance(seq.getObjectAt(index++));
        }
        if (index < seq.size())
        {
            this.otherMetaData = Attributes.getInstance(seq.getObjectAt(index++));
        }
    }

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

    /**
     * <pre>
     * MetaData ::= SEQUENCE {
     *   hashProtected        BOOLEAN,
     *   fileName             UTF8String OPTIONAL,
     *   mediaType            IA5String OPTIONAL,
     *   otherMetaData        Attributes OPTIONAL
     * }
     * </pre>
     * @return
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

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

    public DERUTF8String getFileName()
    {
        return this.fileName;
    }

    public DERIA5String getMediaType()
    {
        return this.mediaType;
    }

    public Attributes getOtherMetaData()
    {
        return otherMetaData;
    }
}
