package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 * <pre>
 *     SequenceOfOctetString ::= SEQUENCE (SIZE(0..MAX)) OF OCTET STRING (SIZE(0..MAX))
 * </pre>
 */
public class SequenceOfOctetString
    extends ASN1Object
{
    private byte[][] octetStrings;

    private SequenceOfOctetString(ASN1Sequence seq)
    {
         this.octetStrings = toByteArrays(seq);
    }

    public static SequenceOfOctetString getInstance(Object o)
    {
        if (o instanceof SequenceOfOctetString)
        {
            return (SequenceOfOctetString)o;
        }
        else if (o != null)
        {
            return new SequenceOfOctetString(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public int size()
    {
        return octetStrings.length;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != octetStrings.length; i++)
        {
            v.add(new DEROctetString(Arrays.clone(octetStrings[i])));
        }

        return new DERSequence(v);
    }

    static byte[][] toByteArrays(ASN1Sequence seq)
    {
        byte[][] octetStrings = new byte[seq.size()][];
        for (int i = 0; i != seq.size(); i++)
        {
            octetStrings[i] = ASN1OctetString.getInstance(seq.getObjectAt(i)).getOctets();
        }

        return octetStrings;
    }
}
