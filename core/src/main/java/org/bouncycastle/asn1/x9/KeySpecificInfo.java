package org.bouncycastle.asn1.x9;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
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
    private ASN1ObjectIdentifier algorithm;
    private ASN1OctetString      counter;

    /**
     * Base constructor.
     *
     * @param algorithm  algorithm identifier for the CEK.
     * @param counter initial counter value for key derivation.
     */
    public KeySpecificInfo(
        ASN1ObjectIdentifier algorithm,
        ASN1OctetString      counter)
    {
        this.algorithm = algorithm;
        this.counter = counter;
    }

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

    private KeySpecificInfo(
        ASN1Sequence  seq)
    {
        Enumeration e = seq.getObjects();

        algorithm = (ASN1ObjectIdentifier)e.nextElement();
        counter = (ASN1OctetString)e.nextElement();
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
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(algorithm);
        v.add(counter);

        return new DERSequence(v);
    }
}
