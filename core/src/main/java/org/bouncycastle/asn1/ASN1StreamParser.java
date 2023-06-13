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

    public ASN1Encodable readObject() throws IOException
    {
        int tagHdr = _in.read();
        if (tagHdr < 0)
        {
            return null;
        }

        return implParseObject(tagHdr);
    }

    ASN1Encodable implParseObject(int tagHdr) throws IOException
    {
        //
        // turn off looking for "00" while we resolve the tag
        //
        set00Check(false);

        //
        // calculate tag number
        //
        int tagNo = ASN1InputStream.readTagNumber(_in, tagHdr);

        //
        // calculate length
        //
        int length = ASN1InputStream.readLength(_in, _limit,
            tagNo == BERTags.BIT_STRING || tagNo == BERTags.OCTET_STRING || tagNo == BERTags.SEQUENCE
                || tagNo == BERTags.SET || tagNo == BERTags.EXTERNAL);

        if (length < 0) // indefinite-length method
        {
            if (0 == (tagHdr & BERTags.CONSTRUCTED))
            {
                throw new IOException("indefinite-length primitive encoding encountered");
            }

            IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(_in, _limit);
            ASN1StreamParser sp = new ASN1StreamParser(indIn, _limit, tmpBuffers);

            int tagClass = tagHdr & BERTags.PRIVATE;
            if (0 != tagClass)
            {
                return new BERTaggedObjectParser(tagClass, tagNo, sp);
            }

            return sp.parseImplicitConstructedIL(tagNo);
        }
        else
        {
            DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(_in, length, _limit);

            if (0 == (tagHdr & BERTags.FLAGS))
            {
                return parseImplicitPrimitive(tagNo, defIn);
            }

            ASN1StreamParser sp = new ASN1StreamParser(defIn, defIn.getLimit(), tmpBuffers);

            int tagClass = tagHdr & BERTags.PRIVATE;
            if (0 != tagClass)
            {
                boolean isConstructed = (tagHdr & BERTags.CONSTRUCTED) != 0;

                return new DLTaggedObjectParser(tagClass, tagNo, isConstructed, sp);
            }

            return sp.parseImplicitConstructedDL(tagNo);
        }
    }

    ASN1Primitive loadTaggedDL(int tagClass, int tagNo, boolean constructed) throws IOException
    {
        if (!constructed)
        {
            byte[] contentsOctets = ((DefiniteLengthInputStream) _in).toByteArray();
            return ASN1TaggedObject.createPrimitive(tagClass, tagNo, contentsOctets);
        }

        ASN1EncodableVector contentsElements = readVector();
        return ASN1TaggedObject.createConstructedDL(tagClass, tagNo, contentsElements);
    }

    ASN1Primitive loadTaggedIL(int tagClass, int tagNo) throws IOException
    {
        ASN1EncodableVector contentsElements = readVector();
        return ASN1TaggedObject.createConstructedIL(tagClass, tagNo, contentsElements);
    }

    ASN1Encodable parseImplicitConstructedDL(int univTagNo) throws IOException
    {
        switch (univTagNo)
        {
        case BERTags.BIT_STRING:
            // TODO[asn1] DLConstructedBitStringParser
            return new BERBitStringParser(this);
        case BERTags.EXTERNAL:
            return new DERExternalParser(this);
        case BERTags.OCTET_STRING:
            // TODO[asn1] DLConstructedOctetStringParser
            return new BEROctetStringParser(this);
        case BERTags.SET:
            return new DLSetParser(this);
        case BERTags.SEQUENCE:
            return new DLSequenceParser(this);
        default:
            // -DM toHexString
            throw new ASN1Exception("unknown DL object encountered: 0x" + Integer.toHexString(univTagNo));
        }
    }

    ASN1Encodable parseImplicitConstructedIL(int univTagNo) throws IOException
    {
        switch (univTagNo)
        {
        case BERTags.BIT_STRING:
            return new BERBitStringParser(this);
        case BERTags.OCTET_STRING:
            return new BEROctetStringParser(this);
        case BERTags.EXTERNAL:
            // TODO[asn1] BERExternalParser
            return new DERExternalParser(this);
        case BERTags.SEQUENCE:
            return new BERSequenceParser(this);
        case BERTags.SET:
            return new BERSetParser(this);
        default:
            throw new ASN1Exception("unknown BER object encountered: 0x" + Integer.toHexString(univTagNo));
        }
    }

    ASN1Encodable parseImplicitPrimitive(int univTagNo) throws IOException
    {
        return parseImplicitPrimitive(univTagNo, (DefiniteLengthInputStream)_in);
    }

    ASN1Encodable parseImplicitPrimitive(int univTagNo, DefiniteLengthInputStream defIn) throws IOException
    {
        // Some primitive encodings can be handled by parsers too...
        switch (univTagNo)
        {
        case BERTags.BIT_STRING:
            return new DLBitStringParser(defIn);
        case BERTags.EXTERNAL:
            throw new ASN1Exception("externals must use constructed encoding (see X.690 8.18)");
        case BERTags.OCTET_STRING:
            return new DEROctetStringParser(defIn);
        case BERTags.SET:
            throw new ASN1Exception("sequences must use constructed encoding (see X.690 8.9.1/8.10.1)");
        case BERTags.SEQUENCE:
            throw new ASN1Exception("sets must use constructed encoding (see X.690 8.11.1/8.12.1)");
        }

        try
        {
            return ASN1InputStream.createPrimitiveDERObject(univTagNo, defIn, tmpBuffers);
        }
        catch (IllegalArgumentException e)
        {
            throw new ASN1Exception("corrupted stream detected", e);
        }
    }

    ASN1Encodable parseObject(int univTagNo) throws IOException
    {
        if (univTagNo < 0 || univTagNo > 30)
        {
            throw new IllegalArgumentException("invalid universal tag number: " + univTagNo);
        }

        int tagHdr = _in.read();
        if (tagHdr < 0)
        {
            return null;
        }

        if ((tagHdr & ~BERTags.CONSTRUCTED) != univTagNo)
        {
            throw new IOException("unexpected identifier encountered: " + tagHdr);
        }

        return implParseObject(tagHdr);
    }

    ASN1TaggedObjectParser parseTaggedObject() throws IOException
    {
        int tagHdr = _in.read();
        if (tagHdr < 0)
        {
            return null;
        }

        int tagClass = tagHdr & BERTags.PRIVATE;
        if (0 == tagClass)
        {
            throw new ASN1Exception("no tagged object found");
        }

        return (ASN1TaggedObjectParser)implParseObject(tagHdr);
    }

    // TODO[asn1] Prefer 'loadVector'
    ASN1EncodableVector readVector() throws IOException
    {
        int tagHdr = _in.read();
        if (tagHdr < 0)
        {
            return new ASN1EncodableVector(0);
        }

        ASN1EncodableVector v = new ASN1EncodableVector();
        do
        {
            ASN1Encodable obj = implParseObject(tagHdr);

            if (obj instanceof InMemoryRepresentable)
            {
                v.add(((InMemoryRepresentable) obj).getLoadedObject());
            }
            else
            {
                v.add(obj.toASN1Primitive());
            }
        }
        while ((tagHdr = _in.read()) >= 0);
        return v;
    }

    private void set00Check(boolean enabled)
    {
        if (_in instanceof IndefiniteLengthInputStream)
        {
            ((IndefiniteLengthInputStream)_in).setEofOn00(enabled);
        }
    }
}
