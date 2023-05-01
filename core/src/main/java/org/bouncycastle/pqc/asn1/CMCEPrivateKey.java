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
 * Classic McEliece private key for fully populated:
 * <pre>
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
 * </pre>
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
        this(version, delta, c, g, alpha, s, null);
    }

    public CMCEPrivateKey(int version, byte[] delta, byte[] c, byte[] g, byte[] alpha, byte[] s, CMCEPublicKey pubKey)
    {
        this.version = version;
        if (version != 0)
        {
             throw new IllegalArgumentException("unrecognized version");
        }
        this.delta = Arrays.clone(delta);
        this.C = Arrays.clone(c);
        this.g = Arrays.clone(g);
        this.alpha = Arrays.clone(alpha);
        this.s = Arrays.clone(s);
        this.PublicKey = pubKey;
    }

    private CMCEPrivateKey(ASN1Sequence seq)
    {
        version = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
        if (version != 0)
        {
             throw new IllegalArgumentException("unrecognized version");
        }

        delta = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());

        C = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());

        g = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets());

        alpha = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(4)).getOctets());

        s = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(5)).getOctets());

        if(seq.size() == 7)
        {
            PublicKey = CMCEPublicKey.getInstance(seq.getObjectAt(6));
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
