package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Base class for an ASN.1 ApplicationSpecific object
 */
// * @deprecated Will be removed. Change application code to handle as
// *             {@link ASN1TaggedObject} only, testing for a
// *             {@link ASN1TaggedObject#getTagClass() tag class} of
// *             {@link BERTags#APPLICATION} in relevant objects, and using
// *             getInstance(ASN1TaggedObject, boolean) methods in the usual way
// *             to extract the base encoding. If using a {@link ASN1StreamParser
// *             stream parser}, handle application-tagged objects using
// *             {@link ASN1TaggedObjectParser} in the usual way, again testing
// *             for a {@link ASN1TaggedObjectParser#getTagClass() tag class} of
// *             {@link BERTags#APPLICATION}.
// */
public abstract class ASN1ApplicationSpecific
//    extends ASN1TaggedObject
    extends ASN1Primitive
    implements ASN1ApplicationSpecificParser
{
    final ASN1TaggedObject taggedObject;

    ASN1ApplicationSpecific(ASN1TaggedObject taggedObject)
    {
//        super(taggedObject.explicit, checkTagClass(taggedObject.tagClass), taggedObject.tagNo, taggedObject.obj);
        checkTagClass(taggedObject.getTagClass());

        this.taggedObject = taggedObject;
    }

    /**
     * Return an ASN1ApplicationSpecific from the passed in object, which may be a byte array, or null.
     *
     * @param obj the object to be converted.
     * @return obj's representation as an ASN1ApplicationSpecific object.
     */
    public static ASN1ApplicationSpecific getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1ApplicationSpecific)
        {
            return (ASN1ApplicationSpecific)obj;
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("Failed to construct object from byte[]: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

//    /** @deprecated Class will be removed */
    protected static int getLengthOfHeader(byte[] data)
    {
        int length = data[1] & 0xff; // TODO: assumes 1 byte tag

        if (length == 0x80)
        {
            return 2;      // indefinite-length encoding
        }

        if (length > 127)
        {
            int size = length & 0x7f;

            // Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be caught here
            if (size > 4)
            {
                throw new IllegalStateException("DER length more than 4 bytes: " + size);
            }

            return size + 2;
        }

        return 2;
    }

    /**
     * Return the tag number associated with this object,
     *
     * @return the application tag number.
     */
    public int getApplicationTag() 
    {
        return taggedObject.getTagNo();
    }

    /**
     * Return the contents of this object as a byte[]
     *
     * @return the encoded contents of the object.
     */
    public byte[] getContents()
    {
        try
        {
            byte[] baseEncoding = taggedObject.getObject().getEncoded(getASN1Encoding());
            if (taggedObject.isExplicit())
            {
                return baseEncoding;
            }

            ByteArrayInputStream input = new ByteArrayInputStream(baseEncoding);
            int tag = input.read();
            ASN1InputStream.readTagNumber(input, tag);
            int length = ASN1InputStream.readLength(input, input.available(), false);
            int remaining = input.available();

            // For indefinite form, account for end-of-contents octets
            int contentsLength = length < 0 ? remaining - 2 : remaining;
            if (contentsLength < 0)
            {
                throw new IllegalStateException();
            }

            byte[] contents = new byte[contentsLength];
            System.arraycopy(baseEncoding, baseEncoding.length - remaining, contents, 0, contentsLength);
            return contents;
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e);
        }
    }

    public final ASN1Primitive getLoadedObject()
    {
        return this;
    }

    /**
     * Return the enclosed object assuming explicit tagging.
     *
     * @return  the resulting object
     * @throws IOException if reconstruction fails.
     */
    public ASN1Primitive getObject()
        throws IOException 
    {
        return taggedObject.getObject();
    }

    /**
     * Return the enclosed object assuming implicit tagging.
     *
     * @param tagNo the type tag that should be applied to the object's contents.
     * @return the resulting object
     * @throws IOException if reconstruction fails.
     */
    public ASN1Primitive getObject(int tagNo) throws IOException
    {
        if (tagNo >= 0x1F)
        {
            throw new IOException("unsupported tag number");
        }

        byte[] orig = getEncoded();
        byte[] tmp = replaceTagNumber(tagNo, orig);

        if ((orig[0] & BERTags.CONSTRUCTED) != 0)
        {
            tmp[0] |= BERTags.CONSTRUCTED;
        }

        return ASN1Primitive.fromByteArray(tmp);
    }

    public ASN1Encodable getObjectParser(int tag, boolean isExplicit) throws IOException
    {
        throw new ASN1Exception("this method only valid for CONTEXT_SPECIFIC tags");
    }

    public ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo) throws IOException
    {
        return taggedObject.parseBaseUniversal(declaredExplicit, baseTagNo);
    }

    public int getTagClass()
    {
        return taggedObject.getTagClass();
    }

    public int getTagNo()
    {
        return taggedObject.getTagNo();
    }

    public boolean hasContextTag(int tagNo)
    {
        return taggedObject.hasContextTag(tagNo);
    }

    public boolean hasTag(int tagClass, int tagNo)
    {
        return taggedObject.hasTag(tagClass, tagNo);
    }

//    /**
//     * ASN1ApplicationSpecific extends ASN1TaggedObject and uses an internal
//     * ASN1TaggedObject for the implementation. This method lets you get the
//     * internal ASN1TaggedObject so that it can be passed to code that uses checks
//     * for subclasses (BER-, DER-, DL- TaggedObject).
//     */
//    public ASN1TaggedObject getTaggedObject()
//    {
//        return taggedObject;
//    }

    boolean asn1Equals(ASN1Primitive o)    {
        ASN1TaggedObject that;
        if (o instanceof ASN1ApplicationSpecific)
        {
            that = ((ASN1ApplicationSpecific)o).taggedObject;
        }
        else if (o instanceof ASN1TaggedObject)
        {
            that = (ASN1TaggedObject)o;
        }
        else
        {
            return false;
        }

        return taggedObject.equals(that);
    }

    public int hashCode()
    {
        return 0;
    }

    /**
     * Return true if the object is marked as constructed, false otherwise.
     *
     * @return true if constructed, otherwise false.
     */
    public boolean isConstructed()
    {
        return taggedObject.isConstructed();
    }

    public ASN1Encodable readObject() throws IOException
    {
        // NOTE: No way to say you're looking for an implicitly-tagged object via ASN1ApplicationSpecificParser
        return taggedObject.getObject();
    }

    int encodedLength(boolean withTag) throws IOException
    {
        return taggedObject.encodedLength(withTag);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        taggedObject.encode(out, withTag);
    }

    abstract String getASN1Encoding();

    ASN1Primitive toDERObject()
    {
        return new DERApplicationSpecific((ASN1TaggedObject)taggedObject.toDERObject());
    }

    ASN1Primitive toDLObject()
    {
        return new DLApplicationSpecific((ASN1TaggedObject)taggedObject.toDLObject());
    }

    private static int checkTagClass(int tagClass)
    {
        if (BERTags.APPLICATION != tagClass)
        {
            throw new IllegalArgumentException();
        }
        return tagClass;
    }

    private static byte[] replaceTagNumber(int newTag, byte[] input)
        throws IOException
    {
        int tagNo = input[0] & 0x1f;
        int index = 1;
        //
        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        //
        if (tagNo == 0x1f)
        {
            int b = input[index++] & 0xff;

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if ((b & 0x7f) == 0) // Note: -1 will pass
            {
                throw new IOException("corrupted stream - invalid high tag number found");
            }

            while ((b & 0x80) != 0)
            {
                b = input[index++] & 0xff;
            }
        }

        byte[] tmp = new byte[input.length - index + 1];

        System.arraycopy(input, index, tmp, 1, tmp.length - 1);

        tmp[0] = (byte)newTag;

        return tmp;
    }

    public String toString()
    {
        return taggedObject.toString();
    }
}
