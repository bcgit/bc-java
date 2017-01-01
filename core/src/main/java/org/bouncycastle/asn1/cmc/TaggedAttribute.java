package org.bouncycastle.asn1.cmc;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Iterator;


import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.pqc.math.linearalgebra.Vector;

/**
 * TaggedAttribute from RFC5272
 * <p>
 * TaggedAttribute ::= SEQUENCE {
 * bodyPartID         BodyPartID,
 * attrType           OBJECT IDENTIFIER,
 * attrValues         SET OF AttributeValue
 * }
 */
public class TaggedAttribute
    extends ASN1Object
{
    private ASN1Integer bodyPartID;
    private ASN1ObjectIdentifier attrType;
    private ASN1Set attrValues = new DERSet();


    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{bodyPartID, attrType, attrValues});
    }

    public static TaggedAttribute getInstance(Object src)
        throws Exception
    {

        if (src instanceof ASN1InputStream)
        {
            ASN1Sequence seq =(ASN1Sequence)((ASN1InputStream)src).readObject();

            return new TaggedAttribute(
                (ASN1Integer)seq.getObjectAt(0),
                (ASN1ObjectIdentifier)seq.getObjectAt(1),
                (ASN1Set)seq.getObjectAt(2));
        }
        else if (src instanceof byte[])
        {
            return getInstance(new ASN1InputStream(new ByteArrayInputStream((byte[])src)));
        }
        else if (src instanceof InputStream)
        {
            return getInstance(new ASN1InputStream((InputStream)src));
        }
        throw new IllegalArgumentException("src not byte[], ASN1InputStream or InputStream");
    }

    public TaggedAttribute(ASN1Integer bodyPartID, ASN1ObjectIdentifier attrType, ASN1Set attrValues)
    {
        this.bodyPartID = bodyPartID;
        this.attrType = attrType;
        this.attrValues = attrValues;
    }

    public ASN1Integer getBodyPartID()
    {
        return bodyPartID;
    }

    public ASN1ObjectIdentifier getAttrType()
    {
        return attrType;
    }

    public ASN1Set getAttrValues()
    {
        return attrValues;
    }

    public void setBodyPartID(ASN1Integer bodyPartID)
    {
        this.bodyPartID = bodyPartID;
    }

    public void setAttrType(ASN1ObjectIdentifier attrType)
    {
        this.attrType = attrType;
    }

    public void setAttrValues(ASN1Set attrValues)
    {
        this.attrValues = attrValues;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        TaggedAttribute that = (TaggedAttribute)o;

        if (!bodyPartID.equals(that.bodyPartID))
        {
            return false;
        }
        if (!attrType.equals(that.attrType))
        {
            return false;
        }

        if (attrValues.size() != ((TaggedAttribute)o).attrValues.size()) {
            return false;
        }

        for (int t=0; t<attrValues.size(); t++)
        {
            if (attrValues.getObjectAt(t).equals(((TaggedAttribute)o).attrValues.getObjectAt(t))) {
                return false;
            }
        }

        return true;

    }

    @Override
    public int hashCode()
    {
        int result = super.hashCode();
        result = 31 * result + bodyPartID.hashCode();
        result = 31 * result + attrType.hashCode();
        result = 31 * result + attrValues.hashCode();
        return result;
    }
}

