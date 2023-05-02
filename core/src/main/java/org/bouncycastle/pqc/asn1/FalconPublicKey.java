package org.bouncycastle.pqc.asn1;


import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Arrays;

/**
 *
 * Classic McEliece Public Key Format.
 * See https://datatracker.ietf.org/doc/draft-uni-qsckeys/ for details.
 * <pre>
 *     FALCONPublicKey := SEQUENCE {
 *         h           OCTET STRING       -- integer polynomial h
 *     }
 * </pre>
 */
public class FalconPublicKey
    extends ASN1Object
{
    private byte[] h;

    public FalconPublicKey(byte[] h)
    {
        this.h = h;
    }

    public byte[] getH()
    {
        return h;
    }

    /**
     * @deprecated use getInstance()
     */
    public FalconPublicKey(ASN1Sequence seq)
    {
        h = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DEROctetString(h));
        return new DERSequence(v);
    }

    public static  FalconPublicKey getInstance(Object o)
    {
        if (o instanceof FalconPublicKey)
        {
            return (FalconPublicKey) o;
        }
        else if (o != null)
        {
            return new FalconPublicKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
