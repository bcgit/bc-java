package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.Exceptions;

/**
 * Base class for ASN.1 primitive objects. These are the actual objects used to generate byte encodings.
 */
public abstract class ASN1Primitive
    extends ASN1Object
{
    ASN1Primitive()
    {
    }

    public void encodeTo(OutputStream output) throws IOException
    {
        ASN1OutputStream asn1Out = ASN1OutputStream.create(output); 
        asn1Out.writePrimitive(this, true);
        asn1Out.flushInternal();
    }

    public void encodeTo(OutputStream output, String encoding) throws IOException
    {
        ASN1OutputStream asn1Out = ASN1OutputStream.create(output, encoding); 
        asn1Out.writePrimitive(this, true);
        asn1Out.flushInternal();
    }

    /**
     * Parse an ASN.1 (BER) encoding from a byte array. Checks there are no extra bytes following the encoding. 
     *
     * @param data the byte array to parse.
     * @return the base ASN.1 object parsed from the byte array.
     * @exception IOException if there is a problem parsing the data, or parsing did not exhaust the available data.
     */
    public static ASN1Primitive fromByteArray(byte[] data)
        throws IOException
    {
        ASN1InputStream aIn = new ASN1InputStream(data);

        try
        {
            ASN1Primitive o = aIn.readObject();

            if (aIn.available() != 0)
            {
                throw new IOException("Extra data detected in stream");
            }

            return o;
        }
        catch (ClassCastException e)
        {
            throw Exceptions.ioException("cannot recognise object in stream", e);
        }
    }

    /**
     * Parse the first ASN.1 (BER) encoding from an {@link InputStream}.The stream is not closed by this method and may
     * contain further data beyond the first ASN.1 encoding.
     *
     * @param data the stream to parse.
     * @return the base ASN.1 object parsed from the stream.
     * @exception IOException if there is a problem parsing the data.
     */
    public static ASN1Primitive fromStream(InputStream input)
        throws IOException
    {
        ASN1InputStream aIn = new ASN1InputStream(input);

        try
        {
            // NOTE: Leave open
            return aIn.readObject();
        }
        catch (ClassCastException e)
        {
            throw Exceptions.ioException("cannot recognise object in stream", e);
        }
    }

    public final boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        return (o instanceof ASN1Encodable) && asn1Equals(((ASN1Encodable)o).toASN1Primitive());
    }

    public final boolean equals(ASN1Encodable other)
    {
        return this == other || (null != other && asn1Equals(other.toASN1Primitive()));
    }

    public final boolean equals(ASN1Primitive other)
    {
        return this == other || asn1Equals(other);
    }

    public final ASN1Primitive toASN1Primitive()
    {
        return this;
    }

    /**
     * Return the current object as one which encodes using Distinguished Encoding Rules.
     *
     * @return a DER version of this.
     */
    ASN1Primitive toDERObject()
    {
        return this;
    }

    /**
     * Return the current object as one which encodes using Definite Length encoding.
     *
     * @return a DL version of this.
     */
    ASN1Primitive toDLObject()
    {
        return this;
    }

    public abstract int hashCode();

    /**
     * Return true if this objected is a CONSTRUCTED one, false otherwise.
     * @return true if CONSTRUCTED bit set on object's tag, false otherwise.
     */
    abstract boolean encodeConstructed();

    abstract int encodedLength(boolean withTag) throws IOException;

    abstract void encode(ASN1OutputStream out, boolean withTag) throws IOException;

    /**
     * Equality (similarity) comparison for two ASN1Primitive objects.
     */
    abstract boolean asn1Equals(ASN1Primitive o);
}