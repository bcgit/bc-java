package org.bouncycastle.asn1.cms;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * RFC 5990 RSA KEM parameters class.
 * <pre>
 *  RsaKemParameters ::= SEQUENCE {
 *     keyDerivationFunction  KeyDerivationFunction,
 *     keyLength              KeyLength
 *   }
 *
 *   KeyDerivationFunction ::= AlgorithmIdentifier
 *   KeyLength ::= INTEGER (1..MAX)
 * </pre>
 */
public class RsaKemParameters
    extends ASN1Object
{
    private final AlgorithmIdentifier keyDerivationFunction;
    private final BigInteger keyLength;

    private RsaKemParameters(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("ASN.1 SEQUENCE should be of length 2");
        }
        this.keyDerivationFunction = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
        this.keyLength = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue();
    }

    public static RsaKemParameters getInstance(
        Object  o)
    {
        if (o instanceof RsaKemParameters)
        {
            return (RsaKemParameters)o;
        }
        else if (o != null)
        {
            return new RsaKemParameters(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * Base constructor.
     *
     * @param keyDerivationFunction algorithm ID describing the key derivation function.
     * @param keyLength length of key to be derived (in bytes).
     */
    public RsaKemParameters(AlgorithmIdentifier keyDerivationFunction, int keyLength)
    {
        this.keyDerivationFunction = keyDerivationFunction;
        this.keyLength = BigInteger.valueOf(keyLength);
    }

    public AlgorithmIdentifier getKeyDerivationFunction()
    {
        return keyDerivationFunction;
    }

    public BigInteger getKeyLength()
    {
        return keyLength;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(keyDerivationFunction);
        v.add(new ASN1Integer(keyLength));

        return new DERSequence(v);
    }
}
