package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Iterator;

/**
 * Note: this class is for processing DER/DL encoded sequences only.
 */
class LazyEncodedSequence
    extends ASN1Sequence
{
    private byte[] encoded;

    LazyEncodedSequence(byte[] encoded) throws IOException
    {
        // NOTE: Initially, the actual 'elements' will be empty
        super();

        this.encoded = encoded;
    }

    public synchronized ASN1Encodable getObjectAt(int index)
    {
        force();

        return super.getObjectAt(index);
    }

    public synchronized Enumeration getObjects()
    {
        if (null != encoded)
        {
            return new LazyConstructionEnumeration(encoded);
        }

        return super.getObjects();
    }

    public synchronized int hashCode()
    {
        force();

        return super.hashCode();
    }

    public synchronized Iterator<ASN1Encodable> iterator()
    {
        force();

        return super.iterator();
    }

    public synchronized int size()
    {
        force();

        return super.size();
    }

    public synchronized ASN1Encodable[] toArray()
    {
        force();

        return super.toArray();
    }

    ASN1Encodable[] toArrayInternal()
    {
        force();

        return super.toArrayInternal();
    }

    synchronized int encodedLength(boolean withTag)
        throws IOException
    {
        if (null != encoded)
        {
            return ASN1OutputStream.getLengthOfEncodingDL(withTag, encoded.length);
        }

        return super.toDLObject().encodedLength(withTag);
    }

    synchronized void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        if (null != encoded)
        {
            out.writeEncodingDL(withTag, BERTags.CONSTRUCTED | BERTags.SEQUENCE, encoded);
        }
        else
        {
            super.toDLObject().encode(out, withTag);
        }
    }

    synchronized ASN1Primitive toDERObject()
    {
        force();

        return super.toDERObject();
    }

    synchronized ASN1Primitive toDLObject()
    {
        force();

        return super.toDLObject();
    }

    private void force()
    {
        if (null != encoded)
        {
            ASN1InputStream aIn = new ASN1InputStream(encoded, true);
            try
            {
                ASN1EncodableVector v = aIn.readVector();
                aIn.close();

                this.elements = v.takeElements();
                this.encoded = null;
            }
            catch (IOException e)
            {
                throw new ASN1ParsingException("malformed ASN.1: " + e, e);
            }
        }
    }
}
