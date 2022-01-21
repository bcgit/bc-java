package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.CrlSeries;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId3;

/**
 * MissingCrlIdentifier ::= SEQUENCE {
 * cracaId    HashedId3,
 * crlSeries  CrlSeries,
 * ...
 * }
 */
public class MissingCrlIdentifier
    extends ASN1Object
{
    private final HashedId3 cracaId;
    private final CrlSeries crlSeries;


    public MissingCrlIdentifier(HashedId3 cracaId, CrlSeries crlSeries)
    {
        this.cracaId = cracaId;
        this.crlSeries = crlSeries;
    }

    public static MissingCrlIdentifier getInstance(Object src)
    {
        if (src instanceof MissingCrlIdentifier)
        {
            return (MissingCrlIdentifier)src;
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(src);
        HashedId3 id = HashedId3.getInstance(seq.getObjectAt(0));
        CrlSeries series = CrlSeries.getInstance(seq.getObjectAt(1));

        return new MissingCrlIdentifier(id, series);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(cracaId, crlSeries);
    }

    public HashedId3 getCracaId()
    {
        return cracaId;
    }

    public CrlSeries getCrlSeries()
    {
        return crlSeries;
    }
}
