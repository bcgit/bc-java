package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 * OOBCertHash ::= SEQUENCE {
 * hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
 * certId      [1] CertId                  OPTIONAL,
 * hashVal         BIT STRING
 * -- hashVal is calculated over the DER encoding of the
 * -- self-signed certificate with the identifier certID.
 * }
 * </pre>
 */
public class OOBCertHash
    extends ASN1Object
{
    private final AlgorithmIdentifier hashAlg;
    private final CertId certId;
    private final ASN1BitString hashVal;

    private OOBCertHash(ASN1Sequence seq)
    {
        int count = seq.size(), pos = 0;

        // hashAlg [0] and certId [1], each optional, then hashVal
        AlgorithmIdentifier hashAlg = null;
        if (pos < count)
        {
            ASN1TaggedObject tag0 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 0);
            if (tag0 != null)
            {
                pos++;
                hashAlg = AlgorithmIdentifier.getInstance(tag0, true);
            }
        }
        CertId certId = null;
        if (pos < count)
        {
            ASN1TaggedObject tag1 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 1);
            if (tag1 != null)
            {
                pos++;
                certId = CertId.getInstance(tag1, true);
            }
        }

        if (pos != count - 1)
        {
            throw new IllegalArgumentException("unexpected element at position " + pos);
        }
        this.hashVal = ASN1BitString.getInstance(seq.getObjectAt(pos));

        this.hashAlg = hashAlg;
        this.certId = certId;
    }

    public OOBCertHash(AlgorithmIdentifier hashAlg, CertId certId, byte[] hashVal)
    {
        this(hashAlg, certId, new DERBitString(hashVal));
    }

    public OOBCertHash(AlgorithmIdentifier hashAlg, CertId certId, DERBitString hashVal)
    {
        this.hashAlg = hashAlg;
        this.certId = certId;
        this.hashVal = hashVal;
    }

    public static OOBCertHash getInstance(Object o)
    {
        if (o instanceof OOBCertHash)
        {
            return (OOBCertHash)o;
        }

        if (o != null)
        {
            return new OOBCertHash(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public AlgorithmIdentifier getHashAlg()
    {
        return hashAlg;
    }

    public CertId getCertId()
    {
        return certId;
    }

    public ASN1BitString getHashVal()
    {
        return hashVal;
    }

    /**
     * <pre>
     * OOBCertHash ::= SEQUENCE {
     *                      hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
     *                      certId      [1] CertId                  OPTIONAL,
     *                      hashVal         BIT STRING
     *                      -- hashVal is calculated over the DER encoding of the
     *                      -- self-signed certificate with the identifier certID.
     *       }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        addOptional(v, 0, hashAlg);
        addOptional(v, 1, certId);

        v.add(hashVal);

        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }
}
