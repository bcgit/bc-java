package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * The OtherName object.
 * <pre>
 * OtherName ::= SEQUENCE {
 *      type-id    OBJECT IDENTIFIER,
 *      value      [0] EXPLICIT ANY DEFINED BY type-id }
 * </pre>
 */
public class OtherName
    extends ASN1Object
{
    private final ASN1ObjectIdentifier typeID;
    private final ASN1Encodable value;

    /**
     * OtherName factory method.
     * @param obj the object used to construct an instance of <code>
     * OtherName</code>. It must be an instance of <code>OtherName
     * </code> or <code>ASN1Sequence</code>.
     * @return the instance of <code>OtherName</code> built from the
     * supplied object.
     * @throws java.lang.IllegalArgumentException if the object passed
     * to the factory is not an instance of <code>OtherName</code> or something that
     * can be converted into an appropriate <code>ASN1Sequence</code>.
     */
    public static OtherName getInstance(
        Object obj)
    {

        if (obj instanceof OtherName)
        {
            return (OtherName)obj;
        }
        else if (obj != null)
        {
            return new OtherName(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Base constructor.
     * @param typeID the type of the other name.
     * @param value the ANY object that represents the value.
     */
    public OtherName(
        ASN1ObjectIdentifier typeID,
        ASN1Encodable value)
    {
        this.typeID = typeID;
        this.value  = value;
    }

    private OtherName(ASN1Sequence seq)
    {
        this.typeID = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.value = ASN1TaggedObject.getInstance(seq.getObjectAt(1)).getObject(); // explicitly tagged
    }

    public ASN1ObjectIdentifier getTypeID()
    {
        return typeID;
    }

    public ASN1Encodable getValue()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(typeID);
        v.add(new DERTaggedObject(true, 0, value));

        return new DERSequence(v);
    }
}
