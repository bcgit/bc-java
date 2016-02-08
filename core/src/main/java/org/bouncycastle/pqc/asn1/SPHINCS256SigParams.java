package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * Used to mark signatures with the correct key details.
 */
public class SPHINCS256SigParams
    extends ASN1Object
{
    private final ASN1Integer version;
    private final SPHINCS256KeyParams keyParams;

    public SPHINCS256SigParams(SPHINCS256KeyParams keyParams)
    {
        this.version = new ASN1Integer(0);
        this.keyParams = keyParams;
    }

    private SPHINCS256SigParams(ASN1Sequence sequence)
    {
        this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
        this.keyParams = SPHINCS256KeyParams.getInstance(sequence.getObjectAt(1));
    }

    public static final SPHINCS256SigParams getInstance(Object o)
    {
        if (o instanceof SPHINCS256SigParams)
        {
            return (SPHINCS256SigParams)o;
        }
        else if (o != null)
        {
            return new SPHINCS256SigParams(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public SPHINCS256KeyParams getKeyParams()
    {
        return keyParams;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(keyParams);

        return new DERSequence(v);
    }
}
