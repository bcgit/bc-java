package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * The DLSet encodes ASN.1 SET value without element ordering,
 * and always using definite length form.
 * <hr>
 * <h2>X.690</h2>
 * <h3>8: Basic encoding rules</h3>
 * <h4>8.11 Encoding of a set value </h4>
 * <b>8.11.1</b> The encoding of a set value shall be constructed
 * <p>
 * <b>8.11.2</b> The contents octets shall consist of the complete
 * encoding of a data value from each of the types listed in the
 * ASN.1 definition of the set type, in an order chosen by the sender,
 * unless the type was referenced with the keyword
 * <b>OPTIONAL</b> or the keyword <b>DEFAULT</b>.
 * <p>
 * <b>8.11.3</b> The encoding of a data value may, but need not,
 * be present for a type which was referenced with the keyword
 * <b>OPTIONAL</b> or the keyword <b>DEFAULT</b>.
 * <blockquote>
 * NOTE &mdash; The order of data values in a set value is not significant,
 * and places no constraints on the order during transfer
 * </blockquote>
 * <h3>9: Canonical encoding rules</h3>
 * <h4>9.3 Set components</h4>
 * The encodings of the component values of a set value shall
 * appear in an order determined by their tags as specified
 * in 8.6 of ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * Additionally, for the purposes of determining the order in which
 * components are encoded when one or more component is an untagged
 * choice type, each untagged choice type is ordered as though it
 * has a tag equal to that of the smallest tag in that choice type
 * or any untagged choice types nested within.
 * <h3>10: Distinguished encoding rules</h3>
 * <h4>10.3 Set components</h4>
 * The encodings of the component values of a set value shall appear
 * in an order determined by their tags as specified
 * in 8.6 of ITU-T Rec. X.680 | ISO/IEC 8824-1.
 * <blockquote>
 * NOTE &mdash; Where a component of the set is an untagged choice type,
 * the location of that component in the ordering will depend on
 * the tag of the choice component being encoded.
 * </blockquote>
 * <h3>11: Restrictions on BER employed by both CER and DER</h3>
 * <h4>11.5 Set and sequence components with default value </h4>
 * The encoding of a set value or sequence value shall not include
 * an encoding for any component value which is equal to
 * its default value.
 */
public class DLSet
    extends ASN1Set
{
    private int bodyLength = -1;

    /**
     * create an empty set
     */
    public DLSet()
    {
    }

    /**
     * @param element - a single object that makes up the set.
     */
    public DLSet(ASN1Encodable element)
    {
        super(element);
    }

    /**
     * @param elementVector - a vector of objects making up the set.
     */
    public DLSet(ASN1EncodableVector elementVector)
    {
        super(elementVector, false);
    }

    /**
     * create a set from an array of objects.
     */
    public DLSet(ASN1Encodable[] elements)
    {
        super(elements, false);
    }

    DLSet(boolean isSorted, ASN1Encodable[] elements)
    {
        super(isSorted, elements);
    }

    private int getBodyLength() throws IOException
    {
        if (bodyLength < 0)
        {
            int count = elements.length;
            int totalLength = 0;

            for (int i = 0; i < count; ++i)
            {
                ASN1Primitive dlObject = elements[i].toASN1Primitive().toDLObject();
                totalLength += dlObject.encodedLength();
            }

            this.bodyLength = totalLength;
        }

        return bodyLength;
    }

    int encodedLength() throws IOException
    {
        int length = getBodyLength();

        return 1 + StreamUtil.calculateBodyLength(length) + length;
    }

    /**
     * A note on the implementation:
     * <p>
     * As DL requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputting SET,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        if (withTag)
        {
            out.write(BERTags.SET | BERTags.CONSTRUCTED);
        }

        ASN1OutputStream dlOut = out.getDLSubStream();

        int count = elements.length;
        if (bodyLength >= 0 || count > 16)
        {
            out.writeLength(getBodyLength());

            for (int i = 0; i < count; ++i)
            {
                dlOut.writePrimitive(elements[i].toASN1Primitive(), true);
            }
        }
        else
        {
            int totalLength = 0;

            ASN1Primitive[] dlObjects = new ASN1Primitive[count];
            for (int i = 0; i < count; ++i)
            {
                ASN1Primitive dlObject = elements[i].toASN1Primitive().toDLObject();
                dlObjects[i] = dlObject;
                totalLength += dlObject.encodedLength();
            }

            this.bodyLength = totalLength;
            out.writeLength(totalLength);

            for (int i = 0; i < count; ++i)
            {
                dlOut.writePrimitive(dlObjects[i], true);
            }
        }
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }
}