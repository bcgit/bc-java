package com.github.gv2011.asn1;

import java.util.Enumeration;

import com.github.gv2011.util.bytes.Bytes;

/**
 * Note: this class is for processing DER/DL encoded sequences only.
 */
class LazyEncodedSequence
    extends ASN1Sequence
{
    private Bytes encoded;

    LazyEncodedSequence(
        final Bytes encoded){
        this.encoded = encoded;
    }

    private void parse()
    {
        final Enumeration<ASN1Encodable> en = new LazyConstructionEnumeration(encoded);

        while (en.hasMoreElements())
        {
            seq.addElement(en.nextElement());
        }

        encoded = null;
    }

    @Override
    public synchronized ASN1Encodable getObjectAt(final int index)
    {
        if (encoded != null)
        {
            parse();
        }

        return super.getObjectAt(index);
    }

    @Override
    public synchronized Enumeration<ASN1Encodable> getObjects()
    {
        if (encoded == null)
        {
            return super.getObjects();
        }

        return new LazyConstructionEnumeration(encoded);
    }

    @Override
    public synchronized int size()
    {
        if (encoded != null)
        {
            parse();
        }

        return super.size();
    }

    @Override
    ASN1Primitive toDERObject()
    {
        if (encoded != null)
        {
            parse();
        }

        return super.toDERObject();
    }

    @Override
    ASN1Primitive toDLObject()
    {
        if (encoded != null)
        {
            parse();
        }

        return super.toDLObject();
    }

    @Override
    int encodedLength()
    {
        if (encoded != null)
        {
            return StreamUtil.typicalLength(encoded);
        }
        else
        {
            return super.toDLObject().encodedLength();
        }
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        if (encoded != null)
        {
            out.writeEncoded(BERTags.SEQUENCE | BERTags.CONSTRUCTED, encoded);
        }
        else
        {
            super.toDLObject().encode(out);
        }
    }
}
