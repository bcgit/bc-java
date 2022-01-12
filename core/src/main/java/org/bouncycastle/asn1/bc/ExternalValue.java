package org.bouncycastle.asn1.bc;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * Based on External Keys And Signatures For Use In Internet PKI
 * draft-ounsworth-pq-external-pubkeys-00
 * <pre>
 *  ExternalValue ::= SEQUENCE {
 *      location GeneralName,    # MUST refer to a DER encoded SubjectPublicKeyInfo/Signature  (may be Base64)
 *      hashAlg AlgorithmIdentifier,
 *      hashVal BIT STRING } 
 * </pre>
 */
public class ExternalValue
    extends ASN1Object
{
    private final GeneralName location;
    private final AlgorithmIdentifier hashAlg;
    private final ASN1BitString hashVal;

    public ExternalValue(GeneralName location, AlgorithmIdentifier hashAlg, byte[] hashVal)
    {
        this.location = location;
        this.hashAlg = hashAlg;
        this.hashVal = new DERBitString(hashVal);
    }

    private ExternalValue(ASN1Sequence seq)
    {
        if (seq.size() == 3)
        {
            location = GeneralName.getInstance(seq.getObjectAt(0));
            hashAlg = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            hashVal = ASN1BitString.getInstance(seq.getObjectAt(2));
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
        return location;
    }

    public AlgorithmIdentifier getHashAlg()
    {
        return hashAlg;
    }

    public ASN1BitString getHashVal()
    {
        return hashVal;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(location);
        v.add(hashAlg);
        v.add(hashVal);

        return new DERSequence(v);
    }
}
