package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Arrays;

/**
 *
 *
 * ASN.1 Encoding for a
 * Classic McEliece private key for fully populated:
 *
 * McEliecePrivateKey ::= SEQUENCE {
 *    Version    INTEGER {v0(0)} -- version (round 3)
 *    delta      OCTET STRING,   -- nonce
 *    C          OCTET STRING,   -- column selections
 *    g          OCTET STRING,   -- monic irreducible polynomial
 *    alpha      OCTET STRING,   -- field orderings
 *    s          OCTET STRING,   -- random n-bit string
 *    PublicKey  [0] IMPLICIT McEliecePublicKey OPTIONAL
 *                                -- see next section
 *    }
 *
 *
 *
 */

public class CMCEPrivateKey
    extends ASN1Object
{
    private int version;
    private byte[] delta;
    private byte[] C;
    private byte[] g;
    private byte[] alpha;
    private byte[] s;
    private CMCEPublicKey PublicKey;

    public CMCEPrivateKey(int version, byte[] delta, byte[] c, byte[] g, byte[] alpha, byte[] s)
    {
        this.version = version;
        this.delta = delta;
        this.C = c;
        this.g = g;
        this.alpha = alpha;
        this.s = s;
    }
    public CMCEPrivateKey(int version, byte[] delta, byte[] c, byte[] g, byte[] alpha, byte[] s, CMCEPublicKey pubKey)
    {
        this.version = version;
        this.delta = delta;
        this.C = c;
        this.g = g;
        this.alpha = alpha;
        this.s = s;
        this.PublicKey = pubKey;
    }

    public CMCEPrivateKey(ASN1Sequence seq)
    {
        version = ((ASN1Integer)seq.getObjectAt(0)).intValueExact();

        delta = Arrays.clone(((ASN1OctetString)seq.getObjectAt(1)).getOctets());

        C = Arrays.clone(((ASN1OctetString)seq.getObjectAt(2)).getOctets());

        g = Arrays.clone(((ASN1OctetString)seq.getObjectAt(3)).getOctets());

        alpha = Arrays.clone(((ASN1OctetString)seq.getObjectAt(4)).getOctets());

        s = Arrays.clone(((ASN1OctetString)seq.getObjectAt(5)).getOctets());

        // todo optional publickey
        if(seq.size() == 7)
        {
            PublicKey = (CMCEPublicKey)seq.getObjectAt(6);
        }


    }

    public int getVersion()
    {
        return version;
    }

    public byte[] getDelta()
    {
        return Arrays.clone(delta);
    }

    public byte[] getC()
    {
        return Arrays.clone(C);
    }

    public byte[] getG()
    {
        return Arrays.clone(g);
    }

    public byte[] getAlpha()
    {
        return Arrays.clone(alpha);
    }

    public byte[] getS()
    {
        return Arrays.clone(s);
    }

    public CMCEPublicKey getPublicKey()
    {
        return PublicKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(version));
        v.add(new DEROctetString(delta));
        v.add(new DEROctetString(C));
        v.add(new DEROctetString(g));
        v.add(new DEROctetString(alpha));
        v.add(new DEROctetString(s));

        // todo optional publickey
        if(PublicKey != null)
        {
            v.add(new CMCEPublicKey(PublicKey.getT()));
        }

        return new DERSequence(v);
    }

    public static  CMCEPrivateKey getInstance(Object o)
    {
        if (o instanceof CMCEPrivateKey)
        {
            return (CMCEPrivateKey)o;
        }
        else if (o != null)
        {
            return new CMCEPrivateKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
