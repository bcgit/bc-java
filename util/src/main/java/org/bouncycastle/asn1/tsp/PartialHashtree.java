package org.bouncycastle.asn1.tsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 * Implementation of PartialHashtree, as defined in RFC 4998.
 * <p>
 * The ASN.1 notation for a PartialHashTree is:
 * <p>
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
     * @return a PartialHashtree instance, or null.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static PartialHashtree getInstance(final Object obj)
    {
        if (obj instanceof PartialHashtree)
        {
            return (PartialHashtree)obj;
        }
        else if (obj != null)
        {
            return new PartialHashtree(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private PartialHashtree(final ASN1Sequence values)
    {
        for (int i = 0; i != values.size(); i++)
        {
            if (!(values.getObjectAt(i) instanceof DEROctetString))
            {
                throw new IllegalArgumentException("unknown object in constructor: " + values
                    .getObjectAt(i).getClass().getName());
            }
        }
        this.values = values;
    }

    public PartialHashtree(byte[] values)
    {
        this(new byte[][] { values });
    }

    public PartialHashtree(byte[][] values)
    {
        ASN1EncodableVector v = new ASN1EncodableVector(values.length);

        for (int i = 0; i != values.length; i++)
        {
            v.add(new DEROctetString(Arrays.clone(values[i])));
        }

        this.values = new DERSequence(v);
    }

    public byte[][] getValues()
    {
        byte[][] rv = new byte[values.size()][];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = Arrays.clone(ASN1OctetString.getInstance(values.getObjectAt(i)).getOctets());
        }

        return rv;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return values;
    }
}
