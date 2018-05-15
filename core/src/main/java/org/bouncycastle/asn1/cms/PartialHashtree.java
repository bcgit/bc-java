package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.*;

/**
 * Implementation of PartialHashtree, as defined in RFC 4998.
 *
 * The ASN.1 notation for a PartialHashTree is:
 *
 * PartialHashtree ::= SEQUENCE OF OCTET STRING
 */
public class PartialHashtree
    extends ASN1Object
{
    /**
     * Hash values that constitute the hash tree, as ASN.1 Octet Strings.
     */
    private ASN1Sequence values;

    /**
     * Return a PartialHashtree from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a PartialHashtree instance, or null.
     */
    public static PartialHashtree getInstance(final Object obj)
    {
        if (obj == null || obj instanceof PartialHashtree)
        {
            return (PartialHashtree) obj;
        }
        else if (obj instanceof DEROctetString)
        {
            return new PartialHashtree(new DERSequence((DEROctetString) obj));
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new PartialHashtree((ASN1Sequence) obj);
        }
        else if (obj instanceof byte[] || obj instanceof ASN1Encodable)
        {
            ASN1Sequence sequence = ASN1Sequence.getInstance(obj);
            return new PartialHashtree(sequence);
        }
        else if (obj instanceof ASN1EncodableVector)
        {
            return new PartialHashtree(new DERSequence((ASN1EncodableVector)obj));
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass()
            .getName());
    }

    private PartialHashtree(final ASN1Sequence values)
    {
        for (int i = 0; i != values.size(); i++)
        {
            if (! (values.getObjectAt(i) instanceof DEROctetString)) {
                throw new IllegalArgumentException("unknown object in constructor: " + values
                    .getObjectAt(i).getClass().getName());
            }
        }
        this.values = values;
    }


    public ASN1Sequence getValues ()
    {
        return values;
    }



    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return values;
    }
}
