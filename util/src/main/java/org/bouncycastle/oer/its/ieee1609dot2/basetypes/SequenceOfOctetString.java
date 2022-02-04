package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     SequenceOfOctetString ::= SEQUENCE (SIZE(0..MAX)) OF OCTET STRING (SIZE(0..MAX))
 * </pre>
 */
public class SequenceOfOctetString
    extends ASN1Object
{
    private final List<ASN1OctetString> octetStrings;

    public SequenceOfOctetString(List<ASN1OctetString> octetStrings)
    {
        this.octetStrings = Collections.unmodifiableList(octetStrings);
    }

    private SequenceOfOctetString(ASN1Sequence seq)
    {
        List<ASN1OctetString> items = new ArrayList<ASN1OctetString>();
        for (Iterator<ASN1Encodable> it = seq.iterator(); it.hasNext(); )
        {
            items.add(DEROctetString.getInstance(it.next()));
        }
        octetStrings = Collections.unmodifiableList(items);
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

    public List<ASN1OctetString> getOctetStrings()
    {
        return octetStrings;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != octetStrings.size(); i++)
        {
            v.add(octetStrings.get(i));
        }

        return new DERSequence(v);
    }
}
