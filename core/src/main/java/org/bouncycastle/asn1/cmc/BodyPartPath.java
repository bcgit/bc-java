package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *    BodyPartPath ::= SEQUENCE SIZE (1..MAX) OF BodyPartID
 * </pre>
 */
public class BodyPartPath
    extends ASN1Object
{
    private final BodyPartID[] bodyPartIDs;

    public static BodyPartPath getInstance(
        Object  obj)
    {
        if (obj instanceof BodyPartPath)
        {
            return (BodyPartPath)obj;
        }

        if (obj != null)
        {
            return new BodyPartPath(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static BodyPartPath getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Construct a BodyPartPath object containing one BodyPartID.
     *
     * @param bodyPartID the BodyPartID to be contained.
     */
    public BodyPartPath(
        BodyPartID  bodyPartID)
    {
        this.bodyPartIDs = new BodyPartID[] { bodyPartID };
    }


    public BodyPartPath(
        BodyPartID[] bodyPartIDs)
    {
        this.bodyPartIDs = Utils.clone(bodyPartIDs);
    }

    private BodyPartPath(
        ASN1Sequence  seq)
    {
        this.bodyPartIDs = Utils.toBodyPartIDArray(seq);
    }

    public BodyPartID[] getBodyPartIDs()
    {
        return Utils.clone(bodyPartIDs);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(bodyPartIDs);
    }
}
