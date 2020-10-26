package org.bouncycastle.its.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     Ieee1609Dot2Data ::= SEQUENCE {
 *         protocolVersion Uint8(3),
 *         content Ieee1609Dot2Content
 *     }
 * </pre>
 */
public class Ieee1609Dot2Data
    extends ASN1Object
{
    private final BigInteger protcolVersion;
    private final Ieee1609Dot2Content content;

    private Ieee1609Dot2Data(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("sequence not length 2");
        }

        protcolVersion = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        content = Ieee1609Dot2Content.getInstance(seq.getObjectAt(1));
    }

    public static Ieee1609Dot2Data getInstance(Object src)
    {
        if (src instanceof Ieee1609Dot2Data)
        {
            return (Ieee1609Dot2Data)src;
        }
        else if (src != null)
        {
            return new Ieee1609Dot2Data(ASN1Sequence.getInstance(src));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        return new DERSequence(v);
    }
}
