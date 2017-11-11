package com.github.gv2011.asn1;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;

import com.github.gv2011.util.bytes.BytesBuilder;

/**
 * Class representing the DER-type External
 */
public class DERExternal
    extends ASN1Primitive
{
    private ASN1ObjectIdentifier directReference;
    private ASN1Integer indirectReference;
    private ASN1Primitive dataValueDescriptor;
    private int encoding;
    private ASN1Primitive externalContent;

    public DERExternal(final ASN1EncodableVector vector)
    {
        int offset = 0;

        ASN1Primitive enc = getObjFromVector(vector, offset);
        if (enc instanceof ASN1ObjectIdentifier)
        {
            directReference = (ASN1ObjectIdentifier)enc;
            offset++;
            enc = getObjFromVector(vector, offset);
        }
        if (enc instanceof ASN1Integer)
        {
            indirectReference = (ASN1Integer) enc;
            offset++;
            enc = getObjFromVector(vector, offset);
        }
        if (!(enc instanceof ASN1TaggedObject))
        {
            dataValueDescriptor = enc;
            offset++;
            enc = getObjFromVector(vector, offset);
        }

        if (vector.size() != offset + 1)
        {
            throw new IllegalArgumentException("input vector too large");
        }

        if (!(enc instanceof ASN1TaggedObject))
        {
            throw new IllegalArgumentException("No tagged object found in vector. Structure doesn't seem to be of type External");
        }
        final ASN1TaggedObject obj = (ASN1TaggedObject)enc;
        setEncoding(obj.getTagNo());
        externalContent = obj.getObject();
    }

    private ASN1Primitive getObjFromVector(final ASN1EncodableVector v, final int index)
    {
        if (v.size() <= index)
        {
            throw new IllegalArgumentException("too few objects in input vector");
        }

        return v.get(index).toASN1Primitive();
    }
    /**
     * Creates a new instance of DERExternal
     * See X.690 for more informations about the meaning of these parameters
     * @param directReference The direct reference or <code>null</code> if not set.
     * @param indirectReference The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param externalData The external data in its encoded form.
     */
    public DERExternal(final ASN1ObjectIdentifier directReference, final ASN1Integer indirectReference, final ASN1Primitive dataValueDescriptor, final DERTaggedObject externalData)
    {
        this(directReference, indirectReference, dataValueDescriptor, externalData.getTagNo(), externalData.toASN1Primitive());
    }

    /**
     * Creates a new instance of DERExternal.
     * See X.690 for more informations about the meaning of these parameters
     * @param directReference The direct reference or <code>null</code> if not set.
     * @param indirectReference The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param encoding The encoding to be used for the external data
     * @param externalData The external data
     */
    public DERExternal(final ASN1ObjectIdentifier directReference, final ASN1Integer indirectReference, final ASN1Primitive dataValueDescriptor, final int encoding, final ASN1Primitive externalData)
    {
        setDirectReference(directReference);
        setIndirectReference(indirectReference);
        setDataValueDescriptor(dataValueDescriptor);
        setEncoding(encoding);
        setExternalContent(externalData.toASN1Primitive());
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
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

    @Override
    boolean isConstructed()
    {
        return true;
    }

    @Override
    int encodedLength()
    {
        return this.getEncoded().size();
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Primitive#encode(org.bouncycastle.asn1.DEROutputStream)
     */
    @Override
    void encode(final ASN1OutputStream out)
    {
        final BytesBuilder baos = newBytesBuilder();
        if (directReference != null)
        {
            directReference.getEncoded(ASN1Encoding.DER).write(baos);
        }
        if (indirectReference != null)
        {
          indirectReference.getEncoded(ASN1Encoding.DER).write(baos);
        }
        if (dataValueDescriptor != null)
        {
          dataValueDescriptor.getEncoded(ASN1Encoding.DER).write(baos);
        }
        final DERTaggedObject obj = new DERTaggedObject(true, encoding, externalContent);
        obj.getEncoded(ASN1Encoding.DER).write(baos);
        out.writeEncoded(BERTags.CONSTRUCTED, BERTags.EXTERNAL, baos.build());
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Primitive#asn1Equals(org.bouncycastle.asn1.ASN1Primitive)
     */
    @Override
    boolean asn1Equals(final ASN1Primitive o)
    {
        if (!(o instanceof DERExternal))
        {
            return false;
        }
        if (this == o)
        {
            return true;
        }
        final DERExternal other = (DERExternal)o;
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
    private void setDataValueDescriptor(final ASN1Primitive dataValueDescriptor)
    {
        this.dataValueDescriptor = dataValueDescriptor;
    }

    /**
     * Sets the direct reference of the external element
     * @param directReferemce The reference
     */
    private void setDirectReference(final ASN1ObjectIdentifier directReferemce)
    {
        directReference = directReferemce;
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
    private void setEncoding(final int encoding)
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
    private void setExternalContent(final ASN1Primitive externalContent)
    {
        this.externalContent = externalContent;
    }

    /**
     * Sets the indirect reference of this element
     * @param indirectReference The reference
     */
    private void setIndirectReference(final ASN1Integer indirectReference)
    {
        this.indirectReference = indirectReference;
    }
}
