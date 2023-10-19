package org.bouncycastle.asn1.bc;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.Arrays;

/**
 * Based on External Keys And Signatures For Use In Internet PKI
 * draft-ounsworth-pq-external-pubkeys-00
 * <pre>
 *  ExternalValue ::= SEQUENCE {
 *      location GeneralNames,    # MUST refer to a DER encoded SubjectPublicKeyInfo/Signature  (may be Base64)
 *      hashAlg AlgorithmIdentifier,
 *      hashVal OCTET STRING }
 * </pre>
 */
public class ExternalValue
    extends ASN1Object
{
    private final GeneralNames location;
    private final AlgorithmIdentifier hashAlg;
    private final byte[] hashValue;

    public ExternalValue(GeneralName location, AlgorithmIdentifier hashAlg, byte[] hashVal)
    {
        this.location = new GeneralNames(location);
        this.hashAlg = hashAlg;
        this.hashValue = Arrays.clone(hashVal);
    }

    private ExternalValue(ASN1Sequence seq)
    {
        if (seq.size() == 3)
        {
            location = GeneralNames.getInstance(seq.getObjectAt(0));
            hashAlg = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            if (seq.getObjectAt(2) instanceof ASN1BitString)    // legacy implementation on 2021 draft
            {
                hashValue = ASN1BitString.getInstance(seq.getObjectAt(2)).getOctets();
            }
            else
            {
                hashValue = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
            }
        }
        else
        {
            throw new IllegalArgumentException("unknown sequence");
        }
    }

    public static ExternalValue getInstance(Object o)
    {
        if (o instanceof ExternalValue)
        {
            return (ExternalValue)o;
        }
        else if (o != null)
        {
            return new ExternalValue(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public GeneralName getLocation()
    {
        return location.getNames()[0];
    }

    public GeneralName[] getLocations()
    {
        return location.getNames();
    }

    public AlgorithmIdentifier getHashAlg()
    {
        return hashAlg;
    }

    public byte[] getHashValue()
    {
        return Arrays.clone(hashValue);
    }

    /**
     * Get the hash value as a BIT STRING.
     *
     * @return the hash value as a BIT STRING
     * @deprecated use getHash(), the internal encoding is now an OCTET STRING
     */
    public ASN1BitString getHashVal()
    {
        return new DERBitString(hashValue);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(location);
        v.add(hashAlg);
        v.add(new DEROctetString(hashValue));

        return new DERSequence(v);
    }
}
