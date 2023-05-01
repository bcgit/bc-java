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
 *
 *    Crystal Kyber Private Key Format.
 *    See https://www.ietf.org/archive/id/draft-uni-qsckeys-kyber-00.html for details.
 *    <pre>
 *        KyberPrivateKey ::= SEQUENCE {
 *        version     INTEGER {v0(0)}   -- version (round 3)
 *        s           OCTET STRING,     -- EMPTY
 *        hpk         OCTET STRING      -- EMPTY
 *        nonce       OCTET STRING,     -- d
 *        publicKey   [0] IMPLICIT KyberPublicKey OPTIONAL,
 *                                      -- see next section
 *        }
 *    </pre>
 */
public class KyberPrivateKey
    extends ASN1Object
{
    private int version;
    private byte[] s;
    private KyberPublicKey publicKey;
    private byte[] hpk;
    private byte[] nonce;

    public KyberPrivateKey(int version, byte[] s, byte[] hpk, byte[] nonce, KyberPublicKey publicKey)
    {
        this.version = version;
        this.s = s;
        this.publicKey = publicKey;
        this.hpk = hpk;
        this.nonce = nonce;
    }

    public KyberPrivateKey(int version, byte[] s, byte[] hpk, byte[] nonce)
    {
        this(version, s, hpk, nonce, null);
    }

    public int getVersion()
    {
        return version;
    }

    public byte[] getS()
    {
        return Arrays.clone(s);
    }

    public KyberPublicKey getPublicKey()
    {
        return publicKey;
    }

    public byte[] getHpk()
    {
        return Arrays.clone(hpk);
    }

    public byte[] getNonce()
    {
        return Arrays.clone(nonce);
    }

    private KyberPrivateKey(ASN1Sequence seq)
    {
        version = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
        if (version != 0)
        {
            throw new IllegalArgumentException("unrecognized version");
        }

        s = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());

        int skipPubKey = 1;
        if (seq.size() == 5)
        {
            skipPubKey = 0; 
            publicKey = KyberPublicKey.getInstance(seq.getObjectAt(2));
        }

        hpk = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(3 - skipPubKey)).getOctets());

        nonce = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(4 - skipPubKey)).getOctets());
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(version));
        v.add(new DEROctetString(s));
        // todo optional publickey
        if(publicKey != null)
        {
            v.add(new KyberPublicKey(publicKey.getT(), publicKey.getRho()));
        }
        v.add(new DEROctetString(hpk));
        v.add(new DEROctetString(nonce));

        return new DERSequence(v);
    }

    public static  KyberPrivateKey getInstance(Object o)
    {
        if (o instanceof KyberPrivateKey)
        {
            return (KyberPrivateKey)o;
        }
        else if (o != null)
        {
            return new KyberPrivateKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

}
