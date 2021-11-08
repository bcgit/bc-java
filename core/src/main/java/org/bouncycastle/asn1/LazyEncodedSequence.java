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

        if (null == encoded)
        {
            throw new NullPointerException("'encoded' cannot be null");
        }

        this.encoded = encoded;
    }

    public ASN1Encodable getObjectAt(int index)
    {
        force();

        return super.getObjectAt(index);
    }

    public Enumeration getObjects()
    {
        byte[] encoded = getContents();
        if (null != encoded)
        {
            return new LazyConstructionEnumeration(encoded);
        }

        return super.getObjects();
    }

    public int hashCode()
    {
        force();

        return super.hashCode();
    }

    public Iterator<ASN1Encodable> iterator()
    {
        force();

        return super.iterator();
    }

    public int size()
    {
        force();

        return super.size();
    }

    public ASN1Encodable[] toArray()
    {
        force();

        return super.toArray();
    }

    ASN1Encodable[] toArrayInternal()
    {
        force();

        return super.toArrayInternal();
    }

    int encodedLength(boolean withTag)
        throws IOException
    {
        byte[] encoded = getContents();
        if (null != encoded)
        {
            return ASN1OutputStream.getLengthOfEncodingDL(withTag, encoded.length);
        }

        return super.toDLObject().encodedLength(withTag);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        byte[] encoded = getContents();
        if (null != encoded)
        {
            out.writeEncodingDL(withTag, BERTags.CONSTRUCTED | BERTags.SEQUENCE, encoded);
            return;
        }

        super.toDLObject().encode(out, withTag);
    }

    ASN1BitString toASN1BitString()
    {
        return ((ASN1Sequence)toDLObject()).toASN1BitString();
    }

    ASN1External toASN1External()
    {
        return ((ASN1Sequence)toDLObject()).toASN1External();
    }

    ASN1OctetString toASN1OctetString()
    {
        return ((ASN1Sequence)toDLObject()).toASN1OctetString();
    }

    ASN1Set toASN1Set()
    {
        return ((ASN1Sequence)toDLObject()).toASN1Set();
    }

    ASN1Primitive toDERObject()
    {
        force();

        return super.toDERObject();
    }

    ASN1Primitive toDLObject()
    {
        force();

        return super.toDLObject();
    }

    private synchronized void force()
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

    private synchronized byte[] getContents()
    {
        return encoded;
    }
}
