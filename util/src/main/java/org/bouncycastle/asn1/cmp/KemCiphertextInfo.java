package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 *    KemCiphertextInfo ::= SEQUENCE {
 *      kem              AlgorithmIdentifier{KEM-ALGORITHM, {...}},
 *      ct               OCTET STRING
 *    }
 * </pre>
 */
public class KemCiphertextInfo
    extends ASN1Object
{
    private final AlgorithmIdentifier kem;
    private final ASN1OctetString ct;

    private KemCiphertextInfo(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("sequence size should 2");
        }

        kem = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        ct = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }


    public KemCiphertextInfo(
        AlgorithmIdentifier kem,
        ASN1OctetString ct)
    {
        this.kem = kem;
        this.ct = ct;
    }

    public static KemCiphertextInfo getInstance(Object o)
    {
        if (o instanceof KemCiphertextInfo)
        {
            return (KemCiphertextInfo)o;
        }

        if (o != null)
        {
            return new KemCiphertextInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public AlgorithmIdentifier getKem()
    {
        return kem;
    }

    public ASN1OctetString getCt()
    {
        return ct;
    }

    /**
     * <pre>
     *    KemCiphertextInfo ::= SEQUENCE {
     *      kem              AlgorithmIdentifier{KEM-ALGORITHM, {...}},
     *      ct               OCTET STRING
     *    }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(kem);
        v.add(ct);

        return new DERSequence(v);
    }
}
