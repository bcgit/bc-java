package org.bouncycastle.asn1;

/**
 * Class representing the Definite-Length-type External
 */
public class DLExternal
    extends ASN1External
{
    /**
     * Construct a Definite-Length EXTERNAL object, the input encoding vector must have exactly two elements on it.
     * <p>
     * Acceptable input formats are:
     * <ul>
     * <li> {@link ASN1ObjectIdentifier} + data {@link DERTaggedObject} (direct reference form)</li>
     * <li> {@link ASN1Integer} + data {@link DERTaggedObject} (indirect reference form)</li>
     * <li> Anything but {@link DERTaggedObject} + data {@link DERTaggedObject} (data value form)</li>
     * </ul>
     *
     * @throws IllegalArgumentException if input size is wrong, or input is not an acceptable format
     * 
     * @deprecated Use {@link DLExternal#DLExternal(DLSequence)} instead.
     */
    public DLExternal(ASN1EncodableVector vector)
    {
        this(DLFactory.createSequence(vector));
    }

    /**
     * Construct a Definite-Length EXTERNAL object, the input sequence must have exactly two elements on it.
     * <p>
     * Acceptable input formats are:
     * <ul>
     * <li> {@link ASN1ObjectIdentifier} + data {@link DERTaggedObject} (direct reference form)</li>
     * <li> {@link ASN1Integer} + data {@link DERTaggedObject} (indirect reference form)</li>
     * <li> Anything but {@link DERTaggedObject} + data {@link DERTaggedObject} (data value form)</li>
     * </ul>
     *
     * @throws IllegalArgumentException if input size is wrong, or input is not an acceptable format
     */
    public DLExternal(DLSequence sequence)
    {
        super(sequence);
    }

    /**
     * Creates a new instance of DERExternal
     * See X.690 for more informations about the meaning of these parameters
     * @param directReference The direct reference or <code>null</code> if not set.
     * @param indirectReference The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param externalData The external data in its encoded form.
     */
    public DLExternal(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference,
        ASN1Primitive dataValueDescriptor, DERTaggedObject externalData)
    {
        super(directReference, indirectReference, dataValueDescriptor, externalData);
    }

    /**
     * Creates a new instance of Definite-Length External.
     * See X.690 for more informations about the meaning of these parameters
     * @param directReference The direct reference or <code>null</code> if not set.
     * @param indirectReference The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param encoding The encoding to be used for the external data
     * @param externalData The external data
     */
    public DLExternal(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference,
        ASN1Primitive dataValueDescriptor, int encoding, ASN1Primitive externalData)
    {
        super(directReference, indirectReference, dataValueDescriptor, encoding, externalData);
    }

    ASN1Sequence buildSequence()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        if (directReference != null)
        {
            v.add(directReference);
        }
        if (indirectReference != null)
        {
            v.add(indirectReference);
        }
        if (dataValueDescriptor != null)
        {
            v.add(dataValueDescriptor.toDLObject());
        }

        v.add(new DLTaggedObject(0 == encoding, encoding, externalContent));

        return new DLSequence(v);
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }
}
