package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Define basic API of ASN.1 Objects
 */
public abstract class ASN1Primitive
    extends ASN1Object
{
    ASN1Primitive()
    {

    }

    /**
     * Create a base ASN.1 object from a byte stream.
     *
     * @param data the byte stream to parse.
     * @return the base ASN.1 object represented by the byte stream.
     * @exception IOException if there is a problem parsing the data.
     */
    public static ASN1Primitive fromByteArray(byte[] data)
        throws IOException
    {
        ASN1InputStream aIn = new ASN1InputStream(data);

        try
        {
            return aIn.readObject();
        }
        catch (ClassCastException e)
        {
            throw new IOException("cannot recognise object in stream");
        }
    }

    @Override // inherits javadoc
    public final boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        return (o instanceof ASN1Encodable) && asn1Equals(((ASN1Encodable)o).toASN1Primitive());
    }

    @Override // inherits javadoc
    public ASN1Primitive toASN1Primitive()
    {
        return this;
    }

    /**
     * Change current object to be encoded as DER object.
     * This is part of DER form serialization.
     */
    ASN1Primitive toDERObject()
    {
        return this;
    }

    /**
     * Change current object to be encoded as DL object.
     * This is part of DL form serialization.
     */
    ASN1Primitive toDLObject()
    {
        return this;
    }

    /**
     * ASN.1 needs stable hashCode() values based on content.
     */
    public abstract int hashCode();

    /**
     * Is this a CONSTRUCTED thing?
     */
    abstract boolean isConstructed();

    /**
     * How long an encode result current type of object produces?
     * This is used for storing on wrapping object's length field (for DER at least.)
     */
    abstract int encodedLength() throws IOException;

    /**
     * Encode current object, and its sub-objects to {@link ASN1OutputStream}.
     */
    abstract void encode(ASN1OutputStream out) throws IOException;

    /**
     * Equality (similarity) comparison for two ASN1Primitive objects.
     */
    abstract boolean asn1Equals(ASN1Primitive o);
}
