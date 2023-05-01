package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 *    Expires 13 May 2022
 *    SABERPrivateKey ::= SEQUENCE {
 *        version     INTEGER  {v0(0)}    -- version (round 3)
 *        z           OCTET STRING,       -- 32-byte random value z
 *        s           OCTET STRING,       -- short integer polynomial s
 *        PublicKey   [0] IMPLICIT SABERPublicKey OPTIONAL,
 *                                        -- see next section
 *        hpk         OCTET STRING        -- H(pk)
 *    }
 *
 */
public class SABERPrivateKey
    extends ASN1Object
{
    private int version;
    private byte[] z;
    private byte[] s;
    private byte[] hpk;

    private SABERPublicKey PublicKey;

    public SABERPrivateKey(int version, byte[] z, byte[] s, byte[] hpk)
    {
        this.version = version;
        if (version != 0)
        {
            throw new IllegalArgumentException("unrecognized version");
        }
        this.z = z;
        this.s = s;
        this.hpk = hpk;
    }

    public SABERPrivateKey(int version, byte[] z, byte[] s, byte[] hpk, SABERPublicKey publicKey)
    {
        this.version = version;
        if (version != 0)
        {
            throw new IllegalArgumentException("unrecognized version");
        }
        this.z = z;
        this.s = s;
        this.hpk = hpk;
        PublicKey = publicKey;
    }


    private SABERPrivateKey(ASN1Sequence seq)
    {
        version = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
        if (version != 0)
        {
            throw new IllegalArgumentException("unrecognized version");
        }

        z = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());

        s = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());

        PublicKey = SABERPublicKey.getInstance(seq.getObjectAt(3));

        hpk = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(4)).getOctets());
    }

    public int getVersion()
    {
        return version;
    }

    public byte[] getZ()
    {
        return z;
    }

    public byte[] getS()
    {
        return s;
    }

    public byte[] getHpk()
    {
        return hpk;
    }

    public SABERPublicKey getPublicKey()
    {
        return PublicKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(version));
        v.add(new DEROctetString(z));
        v.add(new DEROctetString(s));
        //todo optinal pubkey
        //v.add(new SABERPublicKey(PublicKey.getT()));
        v.add(new DEROctetString(hpk));

        return new DERSequence(v);
    }

    public static  SABERPrivateKey getInstance(Object o)
    {
        if (o instanceof SABERPrivateKey)
        {
            return (SABERPrivateKey)o;
        }
        else if (o != null)
        {
            return new SABERPrivateKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
