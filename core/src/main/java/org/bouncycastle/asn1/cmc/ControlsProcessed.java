package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 * -- Inform follow on servers that one or more controls have already been
 * -- processed
 *
 * id-cmc-controlProcessed OBJECT IDENTIFIER ::= {id-cmc 32}
 *
 * ControlsProcessed ::= SEQUENCE {
 *     bodyList              SEQUENCE SIZE(1..MAX) OF BodyPartReference
 * }
 * </pre>
 */
public class ControlsProcessed
    extends ASN1Object
{
    private final ASN1Sequence bodyPartReferences;

    /**
     * Construct a ControlsProcessed object containing one BodyPartReference.
     *
     * @param bodyPartRef the BodyPartReference to be contained.
     */
    public ControlsProcessed(
        BodyPartReference bodyPartRef)
    {
        this.bodyPartReferences = new DERSequence(bodyPartRef);
    }


    public ControlsProcessed(
        BodyPartReference[] bodyList)
    {
        this.bodyPartReferences = new DERSequence(bodyList);
    }


    public static ControlsProcessed getInstance(Object src)
    {
        if (src instanceof ControlsProcessed)
        {
            return (ControlsProcessed)src;
        }
        else if (src != null)
        {
            return new ControlsProcessed(ASN1Sequence.getInstance(src));
        }

        return null;
    }

    private ControlsProcessed(
        ASN1Sequence seq)
    {
        if (seq.size() != 1)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.bodyPartReferences = ASN1Sequence.getInstance(seq.getObjectAt(0));
    }

    public BodyPartReference[] getBodyList()
    {
        BodyPartReference[] tmp = new BodyPartReference[bodyPartReferences.size()];

        for (int i = 0; i != bodyPartReferences.size(); i++)
        {
            tmp[i] = BodyPartReference.getInstance(bodyPartReferences.getObjectAt(i));
        }

        return tmp;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(bodyPartReferences);
    }
}
