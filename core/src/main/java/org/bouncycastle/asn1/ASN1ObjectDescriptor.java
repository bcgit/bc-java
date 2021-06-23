package org.bouncycastle.asn1;

import java.io.IOException;

public abstract class ASN1ObjectDescriptor
    extends ASN1Primitive
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1ObjectDescriptor.class, BERTags.OBJECT_DESCRIPTOR)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * Return an ObjectDescriptor from the passed in object.
     *
     * @param obj an ASN1ObjectDescriptor or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1ObjectDescriptor instance, or null.
     */
    public static ASN1ObjectDescriptor getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1ObjectDescriptor)
        {
            return (ASN1ObjectDescriptor)obj;
        }
        else if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1ObjectDescriptor)
            {
                return (ASN1ObjectDescriptor)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1ObjectDescriptor)TYPE.fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an ObjectDescriptor from a tagged object.
     *
     * @param taggedObject the tagged object holding the object we want.
     * @param explicit     true if the object is meant to be explicitly tagged,
     *                     false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return an ASN1ObjectDescriptor instance, or null.
     */
    public static ASN1ObjectDescriptor getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1ObjectDescriptor)TYPE.getContextInstance(taggedObject, explicit);
    }

    private final ASN1GraphicString baseGraphicString;

    ASN1ObjectDescriptor(ASN1GraphicString baseGraphicString)
    {
        this.baseGraphicString = baseGraphicString;
    }

    public ASN1GraphicString getBaseGraphicString()
    {
        return baseGraphicString;
    }

    final boolean isConstructed()
    {
        return false;
    }

    final int encodedLength(boolean withTag)
    {
        return baseGraphicString.encodedLength(withTag);
    }

    final void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeIdentifier(withTag, BERTags.OBJECT_DESCRIPTOR);
        baseGraphicString.encode(out, false);
    }

    final boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1ObjectDescriptor))
        {
            return false;
        }

        ASN1ObjectDescriptor that = (ASN1ObjectDescriptor)other;

        return this.baseGraphicString.asn1Equals(that.baseGraphicString);
    }

    public final int hashCode()
    {
        return ~baseGraphicString.hashCode();
    }

    static ASN1ObjectDescriptor createPrimitive(byte[] contents)
    {
        return new DERObjectDescriptor(ASN1GraphicString.createPrimitive(contents));
    }
}
