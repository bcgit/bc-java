package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A parser for ASN.1 streams which also returns, where possible, parsers for the objects it encounters.
 */
public class ASN1StreamParser
{
    private final InputStream _in;
    private final int _limit;
    private final byte[][] tmpBuffers;

    public ASN1StreamParser(InputStream in)
    {
        this(in, StreamUtil.findLimit(in));
    }

    public ASN1StreamParser(byte[] encoding)
    {
        this(new ByteArrayInputStream(encoding), encoding.length);
    }

    public ASN1StreamParser(InputStream in, int limit)
    {
        this(in, limit, new byte[11][]);
    }

    ASN1StreamParser(InputStream in, int limit, byte[][] tmpBuffers)
    {
        this._in = in;
        this._limit = limit;
        this.tmpBuffers = tmpBuffers;
    }

    ASN1Encodable readIndef(int tagValue) throws IOException
    {
        // Note: INDEF => CONSTRUCTED

        // TODO There are other tags that may be constructed (e.g. BIT_STRING)
        switch (tagValue)
        {
        case BERTags.EXTERNAL:
            return new DERExternalParser(this);
        case BERTags.OCTET_STRING:
            return new BEROctetStringParser(this);
        case BERTags.SEQUENCE:
            return new BERSequenceParser(this);
        case BERTags.SET:
            return new BERSetParser(this);
        default:
            throw new ASN1Exception("unknown BER object encountered: 0x" + Integer.toHexString(tagValue));
        }
    }

    ASN1Encodable readImplicit(boolean constructed, int tag) throws IOException
    {
        if (_in instanceof IndefiniteLengthInputStream)
        {
            if (!constructed)
            {
                throw new IOException("indefinite-length primitive encoding encountered");
            }
            
            return readIndef(tag);
        }

        if (constructed)
        {
            switch (tag)
            {
            case BERTags.SET:
                return new DLSetParser(this);
            case BERTags.SEQUENCE:
                return new DLSequenceParser(this);
            case BERTags.OCTET_STRING:
                return new BEROctetStringParser(this);
            }
        }
        else
        {
            switch (tag)
            {
            case BERTags.SET:
                throw new ASN1Exception("sequences must use constructed encoding (see X.690 8.9.1/8.10.1)");
            case BERTags.SEQUENCE:
                throw new ASN1Exception("sets must use constructed encoding (see X.690 8.11.1/8.12.1)");
            case BERTags.OCTET_STRING:
                return new DEROctetStringParser((DefiniteLengthInputStream)_in);
            }
        }

        throw new ASN1Exception("implicit tagging not implemented");
    }

    ASN1Primitive readTaggedObject(int tagClass, int tagNo, boolean constructed) throws IOException
    {
        if (!constructed)
        {
            byte[] contentsOctets = ((DefiniteLengthInputStream) _in).toByteArray();
            return ASN1TaggedObject.createPrimitive(tagClass, tagNo, contentsOctets);
        }

        boolean isIL = (_in instanceof IndefiniteLengthInputStream);
        ASN1EncodableVector contentsElements = readVector();
        return ASN1TaggedObject.createConstructed(tagClass, tagNo, isIL, contentsElements);
    }

    public ASN1Encodable readObject()
        throws IOException
    {
        int tag = _in.read();
        if (tag == -1)
        {
            return null;
        }

        //
        // turn of looking for "00" while we resolve the tag
        //
        set00Check(false);

        //
        // calculate tag number
        //
        int tagNo = ASN1InputStream.readTagNumber(_in, tag);

        boolean isConstructed = (tag & BERTags.CONSTRUCTED) != 0;

        //
        // calculate length
        //
        int length = ASN1InputStream.readLength(_in, _limit,
            tagNo == BERTags.OCTET_STRING || tagNo == BERTags.SEQUENCE || tagNo == BERTags.SET || tagNo == BERTags.EXTERNAL);

        if (length < 0) // indefinite-length method
        {
            if (!isConstructed)
            {
                throw new IOException("indefinite-length primitive encoding encountered");
            }

            IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(_in, _limit);
            ASN1StreamParser sp = new ASN1StreamParser(indIn, _limit, tmpBuffers);

            int tagClass = tag & BERTags.PRIVATE;
            if (0 != tagClass)
            {
                if (BERTags.APPLICATION == tagClass)
                {
                    return new BERApplicationSpecificParser(tagNo, true, sp);
                }

                return new BERTaggedObjectParser(tagClass, tagNo, true, sp);
            }

            return sp.readIndef(tagNo);
        }
        else
        {
            DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(_in, length, _limit);

            int tagClass = tag & BERTags.PRIVATE;
            if (0 != tagClass)
            {
                ASN1StreamParser sp = new ASN1StreamParser(defIn, defIn.getLimit(), tmpBuffers);

                /*
                 * TODO Exceptional case can be removed safely once application specific stuff
                 * is removed in favour of uniform tagged object handling. User code might be
                 * checking the specific type at the moment.
                 */
                {
                    if (BERTags.APPLICATION == tagClass)
                    {
                        return new DLApplicationSpecific(isConstructed, tagNo, defIn.toByteArray());
                    }
                }

                return new BERTaggedObjectParser(tagClass, tagNo, isConstructed, sp);
            }

            if (!isConstructed)
            {
                // Some primitive encodings can be handled by parsers too...
                switch (tagNo)
                {
                case BERTags.OCTET_STRING:
                    return new DEROctetStringParser(defIn);
                }

                try
                {
                    return ASN1InputStream.createPrimitiveDERObject(tagNo, defIn, tmpBuffers);
                }
                catch (IllegalArgumentException e)
                {
                    throw new ASN1Exception("corrupted stream detected", e);
                }
            }

            ASN1StreamParser sp = new ASN1StreamParser(defIn, defIn.getLimit(), tmpBuffers);

            // TODO There are other tags that may be constructed (e.g. BIT_STRING)
            switch (tagNo)
            {
            case BERTags.OCTET_STRING:
                //
                // yes, people actually do this...
                //
                return new BEROctetStringParser(sp);
            case BERTags.SEQUENCE:
                return new DLSequenceParser(sp);
            case BERTags.SET:
                return new DLSetParser(sp);
            case BERTags.EXTERNAL:
                return new DERExternalParser(sp);
            default:
                throw new IOException("unknown tag " + tagNo + " encountered");
            }
        }
    }

    private void set00Check(boolean enabled)
    {
        if (_in instanceof IndefiniteLengthInputStream)
        {
            ((IndefiniteLengthInputStream)_in).setEofOn00(enabled);
        }
    }

    ASN1EncodableVector readVector() throws IOException
    {
        ASN1Encodable obj = readObject();
        if (null == obj)
        {
            return new ASN1EncodableVector(0);
        }

        ASN1EncodableVector v = new ASN1EncodableVector();
        do
        {
            if (obj instanceof InMemoryRepresentable)
            {
                v.add(((InMemoryRepresentable)obj).getLoadedObject());
            }
            else
            {
                v.add(obj.toASN1Primitive());
            }
        }
        while ((obj = readObject()) != null);
        return v;
    }
}
