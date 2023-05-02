package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Arrays;

/**
 * See https://datatracker.ietf.org/doc/draft-uni-qsckeys-sphincsplus/00/ for details.
 * ASN.1 Encoding for a
 * SphincsPlus public key for fully populated:
 * <pre>
 *   SPHINCSPPLUSPublicKey := SEQUENCE {
 *     pkseed          OCTET STRING,     --n-byte public key seed
 *     pkroot          OCTET STRING      --n-byte public hypertree root
 *   }
 * </pre>
 */
public class SPHINCSPLUSPublicKey
    extends ASN1Object
{
    private byte[] pkseed;
    private byte[] pkroot;

    public SPHINCSPLUSPublicKey(byte[] pkseed, byte[] pkroot)
    {
        this.pkseed = pkseed;
        this.pkroot = pkroot;
    }

    /**
     * @deprecated use getInstance()
     */
    public SPHINCSPLUSPublicKey(ASN1Sequence seq)
    {
        pkseed = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
        pkroot = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
    }

    public byte[] getPkseed()
    {
        return Arrays.clone(pkseed);
    }
    public byte[] getPkroot()
    {
        return Arrays.clone(pkroot);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DEROctetString(pkseed));
        v.add(new DEROctetString(pkroot));
        return new DERSequence(v);
    }

    public static SPHINCSPLUSPublicKey getInstance(Object o)
    {
        if (o instanceof SPHINCSPLUSPublicKey)
        {
            return (SPHINCSPLUSPublicKey) o;
        }
        else if (o != null)
        {
            return new SPHINCSPLUSPublicKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
