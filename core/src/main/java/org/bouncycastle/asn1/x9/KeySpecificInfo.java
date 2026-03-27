package org.bouncycastle.asn1.x9;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 def for Diffie-Hellman key exchange KeySpecificInfo structure. See
 * RFC 2631, or X9.42, for further details.
 * <pre>
 *  KeySpecificInfo ::= SEQUENCE {
 *      algorithm OBJECT IDENTIFIER,
 *      counter OCTET STRING SIZE (4..4)
 *  }
 * </pre>
 */
public class KeySpecificInfo
    extends ASN1Object
{
    /**
     * Return a KeySpecificInfo object from the passed in object.
     *
     * @param obj an object for conversion or a byte[].
     * @return a KeySpecificInfo
     */
    public static KeySpecificInfo getInstance(Object obj)
    {
        if (obj instanceof KeySpecificInfo)
        {
            return (KeySpecificInfo)obj;
        }
        else if (obj != null)
        {
            return new KeySpecificInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static KeySpecificInfo getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new KeySpecificInfo(ASN1Sequence.getInstance(taggedObject, declaredExplicit));
    }

    public static KeySpecificInfo getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new KeySpecificInfo(ASN1Sequence.getTagged(taggedObject, declaredExplicit));
    }

    private final ASN1ObjectIdentifier algorithm;
    private final ASN1OctetString counter;

    private KeySpecificInfo(ASN1Sequence  seq)
    {
        int count = seq.size();
        if (count != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + count);
        }

        this.algorithm = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.counter = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    /**
     * Base constructor.
     *
     * @param algorithm  algorithm identifier for the CEK.
     * @param counter initial counter value for key derivation.
     */
    public KeySpecificInfo(ASN1ObjectIdentifier algorithm, ASN1OctetString counter)
    {
        if (algorithm == null)
        {
            throw new NullPointerException("'algorithm' cannot be null");
        }
        if (counter == null)
        {
            throw new NullPointerException("'counter' cannot be null");
        }

        this.algorithm = algorithm;
        this.counter = counter;
    }

    /**
     * The object identifier for the CEK wrapping algorithm.
     *
     * @return CEK wrapping algorithm OID.
     */
    public ASN1ObjectIdentifier getAlgorithm()
    {
        return algorithm;
    }

    /**
     * The initial counter value for key derivation.
     *
     * @return initial counter value as a 4 byte octet string (big endian).
     */
    public ASN1OctetString getCounter()
    {
        return counter;
    }

    /**
     * Return an ASN.1 primitive representation of this object.
     *
     * @return a DERSequence containing the KeySpecificInfo values.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(algorithm, counter);
    }
}
