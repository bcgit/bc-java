package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 *
 *    Crystal Kyber Public Key Format.
 *    See https://www.ietf.org/archive/id/draft-uni-qsckeys-kyber-00.html for details.
 *    <pre>
 *        KyberPublicKey ::= SEQUENCE {
 *         t           OCTET STRING,
 *         rho         OCTET STRING
*     }
 *    </pre>
 */
public class KyberPublicKey
    extends ASN1Object

{
    private byte[] t;
    private byte[] rho;

    public KyberPublicKey(byte[] t, byte[] rho)
    {
        this.t = t;
        this.rho = rho;
    }

    /**
     * @deprecated use getInstance()
     */
    public KyberPublicKey(ASN1Sequence seq)
    {
        t = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
        rho = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
    }

    public byte[] getT()
    {
        return Arrays.clone(t);
    }

    public byte[] getRho()
    {
        return Arrays.clone(rho);
    }



    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DEROctetString(t));
        v.add(new DEROctetString(rho));
        return new DERSequence(v);
    }
    public static  KyberPublicKey getInstance(Object o)
    {
        if (o instanceof KyberPublicKey)
        {
            return (KyberPublicKey) o;
        }
        else if (o != null)
        {
            return new KyberPublicKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
