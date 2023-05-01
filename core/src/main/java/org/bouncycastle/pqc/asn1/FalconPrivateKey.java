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
 * ASN.1 Encoding for a
 * FALCON private key for fully populated:
 * <pre>
 * FALCONPrivateKey ::= SEQUENCE {
 *     version     INTEGER {v2(1)}    -- syntax version 2 (round 3)
 *     f           OCTET STRING,      -- short integer polynomial f
 *     g           OCTET STRING,      -- short integer polynomial g
 *     f           OCTET STRING,      -- short integer polynomial F
 *     publicKey   [0] IMPLICIT FALCONPublicKey  OPTIONAL
 *                                    -- see next section
 *     }
 * </pre>
 */
public class FalconPrivateKey
    extends ASN1Object
{
    private int version;
    private byte[] f;
    private byte[] g;
    private byte[] F;
    private FalconPublicKey publicKey;

    public FalconPrivateKey(int version, byte[] f, byte[] g, byte[] f1, FalconPublicKey publicKey)
    {
        this.version = version;
        this.f = f;
        this.g = g;
        F = f1;
        this.publicKey = publicKey;
    }

    public FalconPrivateKey(int version, byte[] f, byte[] g, byte[] f1)
    {
        this(version, f, g, f1, null);
    }

    public int getVersion()
    {
        return version;
    }

    public byte[] getf()
    {
        return Arrays.clone(f);
    }

    public byte[] getF()
    {
        return Arrays.clone(F);
    }

    public FalconPublicKey getPublicKey()
    {
        return publicKey;
    }

    public byte[] getG()
    {
        return Arrays.clone(g);
    }

    private FalconPrivateKey(ASN1Sequence seq)
    {
        version = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
        if (version != 0)
        {
            throw new IllegalArgumentException("unrecognized version");
        }

        f = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());

        g = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());

        F = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets());

        if(seq.size() == 5)
        {
            publicKey = FalconPublicKey.getInstance(seq.getObjectAt(4));
        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(version));
        v.add(new DEROctetString(f));
        v.add(new DEROctetString(g));
        v.add(new DEROctetString(F));

        // todo optional publickey
        if(publicKey != null)
        {
            v.add(new FalconPublicKey(publicKey.getH()));
        }

        return new DERSequence(v);
    }

    public static  FalconPrivateKey getInstance(Object o)
    {
        if (o instanceof FalconPrivateKey)
        {
            return (FalconPrivateKey)o;
        }
        else if (o != null)
        {
            return new FalconPrivateKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

}
