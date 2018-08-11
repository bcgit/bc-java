package org.bouncycastle.asn1.mozilla;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 *  SignedPublicKeyAndChallenge ::= SEQUENCE {
 *    publicKeyAndChallenge PublicKeyAndChallenge,
 *    signatureAlgorithm AlgorithmIdentifier,
 *    signature BIT STRING
 *  }
 *
 *  </pre>
 */
public class SignedPublicKeyAndChallenge
    extends ASN1Object
{
    private final PublicKeyAndChallenge pubKeyAndChal;
    private final ASN1Sequence pkacSeq;

    public static SignedPublicKeyAndChallenge getInstance(Object obj)
    {
        if (obj instanceof SignedPublicKeyAndChallenge)
        {
            return (SignedPublicKeyAndChallenge)obj;
        }
        else if (obj != null)
        {
            return new SignedPublicKeyAndChallenge(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private SignedPublicKeyAndChallenge(ASN1Sequence seq)
    {
        pkacSeq = seq;
        pubKeyAndChal = PublicKeyAndChallenge.getInstance(seq.getObjectAt(0));
    }

    public ASN1Primitive toASN1Primitive()
    {
        return pkacSeq;
    }

    public PublicKeyAndChallenge getPublicKeyAndChallenge()
    {
        return pubKeyAndChal;
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return AlgorithmIdentifier.getInstance(pkacSeq.getObjectAt(1));
    }

    public DERBitString getSignature()
    {
        return DERBitString.getInstance(pkacSeq.getObjectAt(2));
    }
}
