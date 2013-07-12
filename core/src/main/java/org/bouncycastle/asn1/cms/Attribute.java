package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#page-14">RFC 5652</a>
 * <pre>
 * Attribute ::= SEQUENCE {
 *     attrType OBJECT IDENTIFIER,
 *     attrValues SET OF AttributeValue
 * }
 * </pre>
 */

public class Attribute
    extends ASN1Object
{
    private ASN1ObjectIdentifier attrType;
    private ASN1Set             attrValues;

    /**
     * Return an Attribute object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> {@link Attribute} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence ASN1Sequence} input formats with Attribute structure inside
     * <li> null -> null
     * </ul>
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static Attribute getInstance(
        Object o)
    {
        if (o instanceof Attribute)
        {
            return (Attribute)o;
        }
        
        if (o != null)
        {
            return new Attribute(ASN1Sequence.getInstance(o));
        }

        return null;
    }
    
    private Attribute(
        ASN1Sequence seq)
    {
        attrType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        attrValues = (ASN1Set)seq.getObjectAt(1);
    }

    /**
     * @deprecated use ASN1ObjectIdentifier
     */
    public Attribute(
        DERObjectIdentifier attrType,
        ASN1Set             attrValues)
    {
        this.attrType = new ASN1ObjectIdentifier(attrType.getId());
        this.attrValues = attrValues;
    }

    public Attribute(
        ASN1ObjectIdentifier attrType,
        ASN1Set             attrValues)
    {
        this.attrType = attrType;
        this.attrValues = attrValues;
    }

    public ASN1ObjectIdentifier getAttrType()
    {
        return attrType;
    }
    
    public ASN1Set getAttrValues()
    {
        return attrValues;
    }

    public ASN1Encodable[] getAttributeValues()
    {
        return attrValues.toArray();
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(attrType);
        v.add(attrValues);

        return new DERSequence(v);
    }
}
