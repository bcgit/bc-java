package org.bouncycastle.asn1;

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
        if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1External)
            {
                return (ASN1External)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1External)TYPE.fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
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

        ASN1Primitive enc = getObjFromSequence(sequence, offset);
        if (enc instanceof ASN1ObjectIdentifier)
        {
            directReference = (ASN1ObjectIdentifier)enc;
            offset++;
            enc = getObjFromSequence(sequence, offset);
        }
        if (enc instanceof ASN1Integer)
        {
            indirectReference = (ASN1Integer) enc;
            offset++;
            enc = getObjFromSequence(sequence, offset);
        }
        if (!(enc instanceof ASN1TaggedObject))
        {
            dataValueDescriptor = (ASN1Primitive) enc;
            offset++;
            enc = getObjFromSequence(sequence, offset);
        }

        if (sequence.size() != offset + 1)
        {
            throw new IllegalArgumentException("input vector too large");
        }

        if (!(enc instanceof ASN1TaggedObject))
        {
            throw new IllegalArgumentException("No tagged object found in vector. Structure doesn't seem to be of type External");
        }
        ASN1TaggedObject obj = (ASN1TaggedObject)enc;
        setEncoding(obj.getTagNo());
        externalContent = obj.getObject();
    }

    ASN1External(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor, DERTaggedObject externalData)
    {
        this(directReference, indirectReference, dataValueDescriptor, externalData.getTagNo(), externalData.toASN1Primitive());
    }

    ASN1External(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor, int encoding, ASN1Primitive externalData)
    {
        setDirectReference(directReference);
        setIndirectReference(indirectReference);
        setDataValueDescriptor(dataValueDescriptor);
        setEncoding(encoding);
        setExternalContent(externalData.toASN1Primitive());
    }

    ASN1Primitive toDERObject()
    {
        return new DERExternal(directReference, indirectReference, dataValueDescriptor, encoding, externalContent);
    }

    ASN1Primitive toDLObject()
    {
        return new DLExternal(directReference, indirectReference, dataValueDescriptor, encoding, externalContent);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        int ret = 0;
        if (directReference != null)
        {
            ret = directReference.hashCode();
        }
        if (indirectReference != null)
        {
            ret ^= indirectReference.hashCode();
        }
        if (dataValueDescriptor != null)
        {
            ret ^= dataValueDescriptor.hashCode();
        }
        ret ^= externalContent.hashCode();
        return ret;
    }

    boolean isConstructed()
    {
        return true;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Primitive#asn1Equals(org.bouncycastle.asn1.ASN1Primitive)
     */
    boolean asn1Equals(ASN1Primitive o)
    {
        if (!(o instanceof ASN1External))
        {
            return false;
        }
        if (this == o)
        {
            return true;
        }
        ASN1External other = (ASN1External)o;
        if (directReference != null)
        {
            if (other.directReference == null || !other.directReference.equals(directReference))  
            {
                return false;
            }
        }
        if (indirectReference != null)
        {
            if (other.indirectReference == null || !other.indirectReference.equals(indirectReference))
            {
                return false;
            }
        }
        if (dataValueDescriptor != null)
        {
            if (other.dataValueDescriptor == null || !other.dataValueDescriptor.equals(dataValueDescriptor))
            {
                return false;
            }
        }
        return externalContent.equals(other.externalContent);
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
     * Sets the data value descriptor
     * @param dataValueDescriptor The descriptor
     */
    private void setDataValueDescriptor(ASN1Primitive dataValueDescriptor)
    {
        this.dataValueDescriptor = dataValueDescriptor;
    }

    /**
     * Sets the direct reference of the external element
     * @param directReferemce The reference
     */
    private void setDirectReference(ASN1ObjectIdentifier directReferemce)
    {
        this.directReference = directReferemce;
    }
    
    /**
     * Sets the encoding of the content. Valid values are
     * <ul>
     * <li><code>0</code> single-ASN1-type</li>
     * <li><code>1</code> OCTET STRING</li>
     * <li><code>2</code> BIT STRING</li>
     * </ul>
     * @param encoding The encoding
     */
    private void setEncoding(int encoding)
    {
        if (encoding < 0 || encoding > 2)
        {
            throw new IllegalArgumentException("invalid encoding value: " + encoding);
        }
        this.encoding = encoding;
    }
    
    /**
     * Sets the content of this element
     * @param externalContent The content
     */
    private void setExternalContent(ASN1Primitive externalContent)
    {
        this.externalContent = externalContent;
    }
    
    /**
     * Sets the indirect reference of this element
     * @param indirectReference The reference
     */
    private void setIndirectReference(ASN1Integer indirectReference)
    {
        this.indirectReference = indirectReference;
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
