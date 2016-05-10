package com.github.gv2011.bcasn.pqc.asn1;

import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1Integer;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1OctetString;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.DEROctetString;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.util.Arrays;

/**
 * This class implements an ASN.1 encoded GMSS public key. The ASN.1 definition
 * of this structure is:
 * <pre>
 *  GMSSPublicKey        ::= SEQUENCE{
 *      version         INTEGER
 *      publicKey       OCTET STRING
 *  }
 * </pre>
 */
public class GMSSPublicKey
    extends ASN1Object
{
    private ASN1Integer version;
    private byte[] publicKey;

    private GMSSPublicKey(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("size of seq = " + seq.size());
        }

        this.version = ASN1Integer.getInstance(seq.getObjectAt(0));
        this.publicKey = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
    }

    public GMSSPublicKey(byte[] publicKeyBytes)
    {
        this.version = new ASN1Integer(0);
        this.publicKey = publicKeyBytes;
    }

    public static GMSSPublicKey getInstance(Object o)
    {
        if (o instanceof GMSSPublicKey)
        {
            return (GMSSPublicKey)o;
        }
        else if (o != null)
        {
            return new GMSSPublicKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(new DEROctetString(publicKey));

        return new DERSequence(v);
    }
}
