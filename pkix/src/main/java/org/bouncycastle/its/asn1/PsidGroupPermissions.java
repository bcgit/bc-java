package org.bouncycastle.its.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * <pre>
 *     PsidGroupPermissions ::= SEQUENCE {
 *         subjectPermissions SubjectPermissions,
 *         minChainLength INTEGER DEFAULT 1,
 *         chainLengthRange INTEGER DEFAULT 0,
 *         eeType EndEntityType DEFAULT (app)
 *     }
 * </pre>
 */
public class PsidGroupPermissions
    extends ASN1Object
{
    private final SubjectPermissions subjectPermissions;
    private final BigInteger minChainLength;
    private final BigInteger chainLengthRange;
    private final Object eeType;

    private PsidGroupPermissions(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("sequence not length 2");
        }

        this.subjectPermissions = SubjectPermissions.getInstance(seq.getObjectAt(0));
        this.minChainLength = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
        this.chainLengthRange = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue();
        this.eeType = EndEntityType.getInstance(seq.getObjectAt(3));
    }

    public static PsidGroupPermissions getInstance(Object src)
    {
        if (src instanceof PsidGroupPermissions)
        {
            return (PsidGroupPermissions)src;
        }
        else if (src != null)
        {
            return new PsidGroupPermissions(ASN1Sequence.getInstance(src));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
