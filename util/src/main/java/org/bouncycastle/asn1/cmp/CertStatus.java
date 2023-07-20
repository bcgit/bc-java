package org.bouncycastle.asn1.cmp;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1Util;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * CertStatus ::= SEQUENCE {
 * certHash    OCTET STRING,
 * certReqId   INTEGER,
 * statusInfo  PKIStatusInfo OPTIONAL,
 * hashAlg [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}}
 * OPTIONAL
 * }
 */
public class CertStatus
    extends ASN1Object
{
    private final ASN1OctetString certHash;
    private final ASN1Integer certReqId;
    private final PKIStatusInfo statusInfo;
    private final AlgorithmIdentifier hashAlg;

    private CertStatus(ASN1Sequence seq)
    {
        this.certHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
        this.certReqId = ASN1Integer.getInstance(seq.getObjectAt(1));

        PKIStatusInfo statusInfo = null;
        AlgorithmIdentifier hashAlg = null;

        if (seq.size() > 2)
        {
            for (int t = 2; t < seq.size(); t++)
            {
                ASN1Primitive p = seq.getObjectAt(t).toASN1Primitive();
                if (p instanceof ASN1Sequence)
                {
                    statusInfo = PKIStatusInfo.getInstance(p);
                }
                if (p instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject dto = (ASN1TaggedObject)p;
                    if (!dto.hasContextTag(0))
                    {
                        throw new IllegalArgumentException("unknown tag " + ASN1Util.getTagText(dto));
                    }
                    hashAlg = AlgorithmIdentifier.getInstance(dto, true);
                }
            }
        }

        this.statusInfo = statusInfo;
        this.hashAlg = hashAlg;
    }

    public CertStatus(byte[] certHash, BigInteger certReqId)
    {
        this(certHash, new ASN1Integer(certReqId));
    }

    public CertStatus(byte[] certHash, ASN1Integer certReqId)
    {
        this.certHash = new DEROctetString(certHash);
        this.certReqId = certReqId;
        this.statusInfo = null;
        this.hashAlg = null;
    }

    public CertStatus(byte[] certHash, BigInteger certReqId, PKIStatusInfo statusInfo)
    {
        this.certHash = new DEROctetString(certHash);
        this.certReqId = new ASN1Integer(certReqId);
        this.statusInfo = statusInfo;
        this.hashAlg = null;
    }

    public CertStatus(byte[] certHash, BigInteger certReqId, PKIStatusInfo statusInfo, AlgorithmIdentifier hashAlg)
    {
        this.certHash = new DEROctetString(certHash);
        this.certReqId = new ASN1Integer(certReqId);
        this.statusInfo = statusInfo;
        this.hashAlg = hashAlg;
    }

    public static CertStatus getInstance(Object o)
    {
        if (o instanceof CertStatus)
        {
            return (CertStatus)o;
        }

        if (o != null)
        {
            return new CertStatus(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1OctetString getCertHash()
    {
        return certHash;
    }

    public ASN1Integer getCertReqId()
    {
        return certReqId;
    }

    public PKIStatusInfo getStatusInfo()
    {
        return statusInfo;
    }

    public AlgorithmIdentifier getHashAlg()
    {
        return hashAlg;
    }

    /**
     * <pre>
     *
     *  CertStatus ::= SEQUENCE {
     *     certHash    OCTET STRING,
     *     certReqId   INTEGER,
     *     statusInfo  PKIStatusInfo OPTIONAL,
     *     hashAlg [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}} OPTIONAL
     *   }
     *
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(certHash);
        v.add(certReqId);

        if (statusInfo != null)
        {
            v.add(statusInfo);
        }

        if (hashAlg != null)
        {
            v.add(new DERTaggedObject(true, 0, hashAlg));
        }
        return new DERSequence(v);
    }
}
