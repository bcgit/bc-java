package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class OtherKeyAttribute
    extends ASN1Object
{
    private ASN1ObjectIdentifier keyAttrId;
    private ASN1Encodable        keyAttr;

    /**
     * return an OtherKeyAttribute object from the given object.
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static OtherKeyAttribute getInstance(
        Object o)
    {
        if (o == null || o instanceof OtherKeyAttribute)
        {
            return (OtherKeyAttribute)o;
        }
        
        if (o instanceof ASN1Sequence)
        {
            return new OtherKeyAttribute((ASN1Sequence)o);
        }

        throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
    }
    
    public OtherKeyAttribute(
        ASN1Sequence seq)
    {
        keyAttrId = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        keyAttr = seq.getObjectAt(1);
    }

    public OtherKeyAttribute(
        ASN1ObjectIdentifier keyAttrId,
        ASN1Encodable        keyAttr)
    {
        this.keyAttrId = keyAttrId;
        this.keyAttr = keyAttr;
    }

    public ASN1ObjectIdentifier getKeyAttrId()
    {
        return keyAttrId;
    }
    
    public ASN1Encodable getKeyAttr()
    {
        return keyAttr;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * OtherKeyAttribute ::= SEQUENCE {
     *     keyAttrId OBJECT IDENTIFIER,
     *     keyAttr ANY DEFINED BY keyAttrId OPTIONAL
     * }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(keyAttrId);
        v.add(keyAttr);

        return new DERSequence(v);
    }
}
