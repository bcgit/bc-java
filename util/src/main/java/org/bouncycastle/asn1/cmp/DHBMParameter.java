package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * DHBMParameter ::= SEQUENCE {
 * owf                 AlgorithmIdentifier,
 * -- AlgId for a One-Way Function (SHA-1 recommended)
 * mac                 AlgorithmIdentifier
 * -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
 * }   -- or HMAC [RFC2104, RFC2202])
 */
public class DHBMParameter
    extends ASN1Object
{

    private final AlgorithmIdentifier owf;
    private final AlgorithmIdentifier mac;

    private DHBMParameter(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expecting sequence size of 2");
        }


        owf = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
        mac = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
    }

    public DHBMParameter(AlgorithmIdentifier owf, AlgorithmIdentifier mac)
    {
        this.owf = owf;
        this.mac = mac;
    }

    public static DHBMParameter getInstance(Object o)
    {
        if (o instanceof DHBMParameter)
        {
            return (DHBMParameter)o;
        }
        if (o != null)
        {
            return new DHBMParameter(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public AlgorithmIdentifier getOwf()
    {
        return owf;
    }

    public AlgorithmIdentifier getMac()
    {
        return mac;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{owf, mac});
    }
}
