package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Indefinite length SEQUENCE of objects.
 * <p>
 * Length field has value 0x80, and the sequence ends with two bytes of: 0x00, 0x00.
 * </p><p>
 * For X.690 syntax rules, see {@link ASN1Sequence}.
 * </p>
 */
public class BERSequence
    extends ASN1Sequence
{
    /**
     * Create an empty sequence
     */
    public BERSequence()
    {
    }

    /**
     * Create a sequence containing one object
     */
    public BERSequence(ASN1Encodable element)
    {
        super(element);
    }

    /**
     * Create a sequence containing a vector of objects.
     */
    public BERSequence(ASN1EncodableVector elementVector)
    {
        super(elementVector);
    }

    /**
     * Create a sequence containing an array of objects.
     */
    public BERSequence(ASN1Encodable[] elements)
    {
        super(elements);
    }

    int encodedLength(boolean withTag) throws IOException
    {
        int totalLength = withTag ? 4 : 3;

        for (int i = 0, count = elements.length; i < count; ++i)
        {
            ASN1Primitive p = elements[i].toASN1Primitive();
            totalLength += p.encodedLength(true);
        }

        return totalLength;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingIL(withTag, BERTags.CONSTRUCTED | BERTags.SEQUENCE, elements);
    }

    ASN1BitString toASN1BitString()
    {
        return new BERBitString(getConstructedBitStrings());
    }

    ASN1External toASN1External()
    {
        // TODO There is currently no BERExternal class
        return ((ASN1Sequence)toDLObject()).toASN1External();
    }

    ASN1OctetString toASN1OctetString()
    {
        return new BEROctetString(getConstructedOctetStrings());
    }

    ASN1Set toASN1Set()
    {
        return new BERSet(false, toArrayInternal());
    }
}
