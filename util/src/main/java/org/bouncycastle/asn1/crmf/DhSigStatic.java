package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.util.Arrays;

/**
 * From RFC 2875 for Diffie-Hellman POP.
 * <pre>
 *     DhSigStatic ::= SEQUENCE {
 *         IssuerAndSerial IssuerAndSerialNumber OPTIONAL,
 *         hashValue       MessageDigest
 *     }
 * </pre>
 */
public class DhSigStatic
    extends ASN1Object
{
    private final IssuerAndSerialNumber issuerAndSerial;
    private final ASN1OctetString hashValue;

    public DhSigStatic(byte[] hashValue)
    {
        this(null, hashValue);
    }

    public DhSigStatic(IssuerAndSerialNumber issuerAndSerial, byte[] hashValue)
    {
        this.issuerAndSerial = issuerAndSerial;
        this.hashValue = new DEROctetString(Arrays.clone(hashValue));
    }

    public static DhSigStatic getInstance(Object o)
    {
        if (o instanceof DhSigStatic)
        {
            return (DhSigStatic)o;
        }
        else if (o != null)
        {
            return new DhSigStatic(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private DhSigStatic(ASN1Sequence seq)
    {
        if (seq.size() == 1)
        {
            issuerAndSerial = null;
            hashValue = ASN1OctetString.getInstance(seq.getObjectAt(0));
        }
        else if (seq.size() == 2)
        {
            issuerAndSerial = IssuerAndSerialNumber.getInstance(seq.getObjectAt(0));
            hashValue = ASN1OctetString.getInstance(seq.getObjectAt(1));
        }
        else
        {
            throw new IllegalArgumentException("sequence wrong length for DhSigStatic");
        }
    }

    public IssuerAndSerialNumber getIssuerAndSerial()
    {
        return issuerAndSerial;
    }

    public byte[] getHashValue()
    {
        return Arrays.clone(hashValue.getOctets());
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        if (issuerAndSerial != null)
        {
            v.add(issuerAndSerial);
        }

        v.add(hashValue);

        return new DERSequence(v);
    }
}
