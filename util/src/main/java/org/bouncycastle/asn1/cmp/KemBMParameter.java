package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 *  KemBMParameter ::= SEQUENCE {
 *      kdf              AlgorithmIdentifier{KEY-DERIVATION, {...}},
 *      len              INTEGER (1..MAX),
 *      mac              AlgorithmIdentifier{MAC-ALGORITHM, {...}}
 *   }
 * </pre>
 */
public class KemBMParameter
    extends ASN1Object
{
    private final AlgorithmIdentifier kdf;
    private final ASN1Integer len;
    private final AlgorithmIdentifier mac;

    private KemBMParameter(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("sequence size should 3");
        }

        kdf = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        len = ASN1Integer.getInstance(seq.getObjectAt(1));
        mac = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
    }

    public KemBMParameter(
        AlgorithmIdentifier kdf,
        ASN1Integer len,
        AlgorithmIdentifier mac)
    {
        this.kdf = kdf;
        this.len = len;
        this.mac = mac;
    }

    public KemBMParameter(
        AlgorithmIdentifier kdf,
        long len,
        AlgorithmIdentifier mac)
    {
        this(kdf, new ASN1Integer(len), mac);
    }

    public static KemBMParameter getInstance(Object o)
    {
        if (o instanceof KemBMParameter)
        {
            return (KemBMParameter)o;
        }

        if (o != null)
        {
            return new KemBMParameter(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public AlgorithmIdentifier getKdf()
    {
        return kdf;
    }

    public ASN1Integer getLen()
    {
        return len;
    }

    public AlgorithmIdentifier getMac()
    {
        return mac;
    }

    /**
     * <pre>
     *  KemBMParameter ::= SEQUENCE {
     *      kdf              AlgorithmIdentifier{KEY-DERIVATION, {...}},
     *      len              INTEGER (1..MAX),
     *      mac              AlgorithmIdentifier{MAC-ALGORITHM, {...}}
     *    }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(kdf);
        v.add(len);
        v.add(mac);

        return new DERSequence(v);
    }
}
