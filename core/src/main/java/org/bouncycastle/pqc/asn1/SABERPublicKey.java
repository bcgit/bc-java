package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Arrays;

/**
 *    Expires 13 May 2022
 *    SABERPublicKey := SEQUENCE {
 *        seed_A      OCTET STRING,        -- 32-byte seed
 *        b           OCTET STRING         -- short integer polynomial b
 *    }
 *
 */
public class SABERPublicKey
    extends ASN1Object
{
    private byte[] seed_A;
    private byte[] b;

    public SABERPublicKey(byte[] seed_A, byte[] b)
    {
        this.seed_A = seed_A;
        this.b = b;
    }

    private SABERPublicKey(ASN1Sequence seq)
    {
        seed_A = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());

        b = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
    }

    public byte[] getSeed_A()
    {
        return seed_A;
    }

    public byte[] getB()
    {
        return b;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DEROctetString(seed_A));
        v.add(new DEROctetString(b));

        return new DERSequence(v);
    }

    public static SABERPublicKey getInstance(Object o)
    {
        if (o instanceof SABERPublicKey)
        {
            return  (SABERPublicKey)o;
        }
        else if (o != null)
        {
            return new SABERPublicKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }


}
