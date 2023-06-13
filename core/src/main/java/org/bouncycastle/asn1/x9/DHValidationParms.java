package org.bouncycastle.asn1.x9;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * @deprecated use ValidationParams
 */
public class DHValidationParms extends ASN1Object
{
    private ASN1BitString seed;
    private ASN1Integer pgenCounter;

    public static DHValidationParms getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static DHValidationParms getInstance(Object obj)
    {
        if (obj instanceof DHValidationParms)
        {
            return (DHValidationParms)obj;
        }
        else if (obj != null)
        {
            return new DHValidationParms(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public DHValidationParms(ASN1BitString seed, ASN1Integer pgenCounter)
    {
        if (seed == null)
        {
            throw new IllegalArgumentException("'seed' cannot be null");
        }
        if (pgenCounter == null)
        {
            throw new IllegalArgumentException("'pgenCounter' cannot be null");
        }

        this.seed = seed;
        this.pgenCounter = pgenCounter;
    }

    private DHValidationParms(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        this.seed = ASN1BitString.getInstance(seq.getObjectAt(0));
        this.pgenCounter = ASN1Integer.getInstance(seq.getObjectAt(1));
    }

    public ASN1BitString getSeed()
    {
        return this.seed;
    }

    public ASN1Integer getPgenCounter()
    {
        return this.pgenCounter;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.seed);
        v.add(this.pgenCounter);
        return new DERSequence(v);
    }
}
