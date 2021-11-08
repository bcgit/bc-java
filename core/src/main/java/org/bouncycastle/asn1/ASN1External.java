package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Objects;

/**
 * Class representing the DER-type External
 */
public abstract class ASN1External
    extends ASN1Primitive
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1External.class, BERTags.EXTERNAL)
    {
        ASN1Primitive fromImplicitConstructed(ASN1Sequence sequence)
        {
            // TODO Ideally ASN1External would have no subclasses and just hold the sequence
            return sequence.toASN1External();
        }
    };

    public static ASN1External getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1External)
        {
            return (ASN1External)obj;
        }
        else if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1External)
            {
                return (ASN1External)primitive;
            }
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return (ASN1External)TYPE.fromByteArray((byte[])obj);
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct external from byte[]: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1External getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1External)TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1ObjectIdentifier directReference;
    ASN1Integer indirectReference;
    // TODO Actually use ASN1ObjectDescriptor for this
    ASN1Primitive dataValueDescriptor;
    int encoding;
    ASN1Primitive externalContent;

    ASN1External(ASN1Sequence sequence)
    {
        int offset = 0;

        ASN1Primitive asn1 = getObjFromSequence(sequence, offset);
        if (asn1 instanceof ASN1ObjectIdentifier)
        {
            directReference = (ASN1ObjectIdentifier)asn1;
            asn1 = getObjFromSequence(sequence, ++offset);
        }
        if (asn1 instanceof ASN1Integer)
        {
            indirectReference = (ASN1Integer)asn1;
            asn1 = getObjFromSequence(sequence, ++offset);
        }
        if (!(asn1 instanceof ASN1TaggedObject))
        {
            dataValueDescriptor = asn1;
            asn1 = getObjFromSequence(sequence, ++offset);
        }

        if (sequence.size() != offset + 1)
        {
            throw new IllegalArgumentException("input sequence too large");
        }

        if (!(asn1 instanceof ASN1TaggedObject))
        {
            throw new IllegalArgumentException(
                "No tagged object found in sequence. Structure doesn't seem to be of type External");
        }

        ASN1TaggedObject obj = (ASN1TaggedObject)asn1;
        this.encoding = checkEncoding(obj.getTagNo());
        this.externalContent = getExternalContent(obj);
    }

    ASN1External(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor,
        DERTaggedObject externalData)
    {
        this.directReference = directReference;
        this.indirectReference = indirectReference;
        this.dataValueDescriptor = dataValueDescriptor;
        this.encoding = checkEncoding(externalData.getTagNo());
        this.externalContent = getExternalContent(externalData);
    }

    ASN1External(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor,
        int encoding, ASN1Primitive externalData)
    {
        this.directReference = directReference;
        this.indirectReference = indirectReference;
        this.dataValueDescriptor = dataValueDescriptor;
        this.encoding = checkEncoding(encoding);
        this.externalContent = checkExternalContent(encoding, externalData);
    }

    abstract ASN1Sequence buildSequence();

    int encodedLength(boolean withTag) throws IOException
    {
        return buildSequence().encodedLength(withTag);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeIdentifier(withTag, BERTags.CONSTRUCTED | BERTags.EXTERNAL);
        buildSequence().encode(out, false);
    }

    ASN1Primitive toDERObject()
    {
        return new DERExternal(directReference, indirectReference, dataValueDescriptor, encoding, externalContent);
    }

    ASN1Primitive toDLObject()
    {
        return new DLExternal(directReference, indirectReference, dataValueDescriptor, encoding, externalContent);
    }

    public int hashCode()
    {
        return Objects.hashCode(this.directReference)
            ^  Objects.hashCode(this.indirectReference)
            ^  Objects.hashCode(this.dataValueDescriptor)
            ^  this.encoding
            ^  this.externalContent.hashCode();
    }

    boolean encodeConstructed()
    {
        return true;
    }

    boolean asn1Equals(ASN1Primitive primitive)
    {
        if (this == primitive)
        {
            return true;
        }
        if (!(primitive instanceof ASN1External))
        {
            return false;
        }

        ASN1External that = (ASN1External)primitive;

        return Objects.areEqual(this.directReference, that.directReference)
            && Objects.areEqual(this.indirectReference, that.indirectReference)
            && Objects.areEqual(this.dataValueDescriptor, that.dataValueDescriptor)
            && this.encoding == that.encoding
            && this.externalContent.equals(that.externalContent);
    }

    /**
     * Returns the data value descriptor
     * @return The descriptor
     */
    public ASN1Primitive getDataValueDescriptor()
    {
        return dataValueDescriptor;
    }

    /**
     * Returns the direct reference of the external element
     * @return The reference
     */
    public ASN1ObjectIdentifier getDirectReference()
    {
        return directReference;
    }

    /**
     * Returns the encoding of the content. Valid values are
     * <ul>
     * <li><code>0</code> single-ASN1-type</li>
     * <li><code>1</code> OCTET STRING</li>
     * <li><code>2</code> BIT STRING</li>
     * </ul>
     * @return The encoding
     */
    public int getEncoding()
    {
        return encoding;
    }

    /**
     * Returns the content of this element
     * @return The content
     */
    public ASN1Primitive getExternalContent()
    {
        return externalContent;
    }

    /**
     * Returns the indirect reference of this element
     * @return The reference
     */
    public ASN1Integer getIndirectReference()
    {
        return indirectReference;
    }

    /**
     * Checks the encoding of the content. Valid values are
     * <ul>
     * <li><code>0</code> single-ASN1-type</li>
     * <li><code>1</code> OCTET STRING</li>
     * <li><code>2</code> BIT STRING</li>
     * </ul>
     * @param encoding The encoding
     */
    private static int checkEncoding(int encoding)
    {
        if (encoding < 0 || encoding > 2)
        {
            throw new IllegalArgumentException("invalid encoding value: " + encoding);
        }

        return encoding;
    }

    private static ASN1Primitive checkExternalContent(int tagNo, ASN1Primitive externalContent)
    {
        switch (tagNo)
        {
        case 1:
            return ASN1OctetString.TYPE.checkedCast(externalContent);
        case 2:
            return ASN1BitString.TYPE.checkedCast(externalContent);
        default:
            return externalContent;
        }
    }

    private static ASN1Primitive getExternalContent(ASN1TaggedObject encoding)
    {
        int tagClass = encoding.getTagClass(), tagNo = encoding.getTagNo();
        if (BERTags.CONTEXT_SPECIFIC != tagClass)
        {
            throw new IllegalArgumentException("invalid tag: " + ASN1Util.getTagText(tagClass, tagNo));
        }

        switch (tagNo)
        {
        case 0:
            return encoding.getExplicitBaseObject().toASN1Primitive();
        case 1:
            return ASN1OctetString.getInstance(encoding, false);
        case 2:
            return ASN1BitString.getInstance(encoding, false);
        default:
            throw new IllegalArgumentException("invalid tag: " + ASN1Util.getTagText(tagClass, tagNo));
        }
    }

    private static ASN1Primitive getObjFromSequence(ASN1Sequence sequence, int index)
    {
        if (sequence.size() <= index)
        {
            throw new IllegalArgumentException("too few objects in input sequence");
        }

        return sequence.getObjectAt(index).toASN1Primitive();
    }
}
