package org.bouncycastle.asn1.ocsp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class CertID
    extends ASN1Object
{
    AlgorithmIdentifier    hashAlgorithm;
    ASN1OctetString        issuerNameHash;
    ASN1OctetString        issuerKeyHash;
    ASN1Integer            serialNumber;

    public CertID(
        AlgorithmIdentifier hashAlgorithm,
        ASN1OctetString     issuerNameHash,
        ASN1OctetString     issuerKeyHash,
        ASN1Integer         serialNumber)
    {
        this.hashAlgorithm = hashAlgorithm;
        this.issuerNameHash = issuerNameHash;
        this.issuerKeyHash = issuerKeyHash;
        this.serialNumber = serialNumber;
    }

    private CertID(
        ASN1Sequence    seq)
    {
        hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        issuerNameHash = (ASN1OctetString)seq.getObjectAt(1);
        issuerKeyHash = (ASN1OctetString)seq.getObjectAt(2);
        serialNumber = (ASN1Integer)seq.getObjectAt(3);
    }

    public static CertID getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertID getInstance(
        Object  obj)
    {
        if (obj instanceof CertID)
        {
            return (CertID)obj;
        }
        else if (obj != null)
        {
            return new CertID(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        return hashAlgorithm;
    }

    public ASN1OctetString getIssuerNameHash()
    {
        return issuerNameHash;
    }

    public ASN1OctetString getIssuerKeyHash()
    {
        return issuerKeyHash;
    }

    public ASN1Integer getSerialNumber()
    {
        return serialNumber;
    }

    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (o instanceof ASN1Encodable)
        {
            try
            {
                CertID other = CertID.getInstance(o);

                if (!this.hashAlgorithm.getAlgorithm().equals(other.hashAlgorithm.getAlgorithm()))
                {
                    return false;
                }
                if (!isEqual(this.hashAlgorithm.getParameters(), other.hashAlgorithm.getParameters()))
                {
                    return false;
                }

                return issuerNameHash.equals(other.issuerNameHash)
                    && issuerKeyHash.equals(other.issuerKeyHash)
                    && serialNumber.equals(other.serialNumber);
            }
            catch (Exception e)
            {
                return false;
            }
        }

        return false;
    }

    public int hashCode()
    {
        ASN1Encodable params = hashAlgorithm.getParameters();
        int hashCode = (params == null || DERNull.INSTANCE.equals(params)) ? 0 : params.hashCode();

        return hashCode + 7 * (hashAlgorithm.getAlgorithm().hashCode()
            + 7 * (issuerNameHash.hashCode() + 7 * (issuerKeyHash.hashCode() + 7 * serialNumber.hashCode())));
    }

    private boolean isEqual(ASN1Encodable a, ASN1Encodable b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null)
        {
            return DERNull.INSTANCE.equals(b);
        }
        else
        {
            if (DERNull.INSTANCE.equals(a) && b == null)
            {
                return true;
            }

            return a.equals(b);
        }
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * CertID          ::=     SEQUENCE {
     *     hashAlgorithm       AlgorithmIdentifier,
     *     issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
     *     issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
     *     serialNumber        CertificateSerialNumber }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(hashAlgorithm);
        v.add(issuerNameHash);
        v.add(issuerKeyHash);
        v.add(serialNumber);

        return new DERSequence(v);
    }
}
