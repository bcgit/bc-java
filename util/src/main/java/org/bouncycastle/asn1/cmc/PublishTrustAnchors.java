package org.bouncycastle.asn1.cmc;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

/**
 * <pre>
 *
 * PublishTrustAnchors ::= SEQUENCE {
 *     seqNumber      INTEGER,
 *     hashAlgorithm  AlgorithmIdentifier,
 *     anchorHashes     SEQUENCE OF OCTET STRING
 * }
 * </pre>
 */
public class PublishTrustAnchors
    extends ASN1Object
{
    private final ASN1Integer seqNumber;
    private final AlgorithmIdentifier hashAlgorithm;
    private final ASN1Sequence anchorHashes;

    public PublishTrustAnchors(BigInteger seqNumber, AlgorithmIdentifier hashAlgorithm, byte[][] anchorHashes)
    {
        this.seqNumber = new ASN1Integer(seqNumber);
        this.hashAlgorithm = hashAlgorithm;

        ASN1EncodableVector v = new ASN1EncodableVector(anchorHashes.length);
        for (int i = 0; i != anchorHashes.length; i++)
        {
             v.add(new DEROctetString(Arrays.clone(anchorHashes[i])));
        }
        this.anchorHashes = new DERSequence(v);
    }

    private PublishTrustAnchors(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.seqNumber = ASN1Integer.getInstance(seq.getObjectAt(0));
        this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.anchorHashes = ASN1Sequence.getInstance(seq.getObjectAt(2));
    }

    public static PublishTrustAnchors getInstance(Object o)
    {
        if (o instanceof PublishTrustAnchors)
        {
            return (PublishTrustAnchors)o;
        }

        if (o != null)
        {
            return new PublishTrustAnchors(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public BigInteger getSeqNumber()
    {
        return seqNumber.getValue();
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        return hashAlgorithm;
    }

    public byte[][] getAnchorHashes()
    {
        byte[][] hashes = new byte[anchorHashes.size()][];

        for (int i = 0; i != hashes.length; i++)
        {
            hashes[i] = Arrays.clone(ASN1OctetString.getInstance(anchorHashes.getObjectAt(i)).getOctets());
        }

        return hashes;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(seqNumber);
        v.add(hashAlgorithm);
        v.add(anchorHashes);

        return new DERSequence(v);
    }
}
