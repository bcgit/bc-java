package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.io.Streams;

/**
 * A general purpose ASN.1 decoder - note: this class differs from the
 * others in that it returns null after it has read the last object in
 * the stream. If an ASN.1 NULL is encountered a DER/BER Null object is
 * returned.
 */
public class ASN1InputStream
    extends FilterInputStream
    implements BERTags
{
    private final int limit;
    private final boolean lazyEvaluate;
    private final byte[][] tmpBuffers;

    public ASN1InputStream(InputStream is)
    {
        this(is, StreamUtil.findLimit(is));
    }

    /**
     * Create an ASN1InputStream based on the input byte array. The length of DER objects in
     * the stream is automatically limited to the length of the input array.
     * 
     * @param input array containing ASN.1 encoded data.
     */
    public ASN1InputStream(byte[] input)
    {
        this(new ByteArrayInputStream(input), input.length);
    }

    /**
     * Create an ASN1InputStream based on the input byte array. The length of DER objects in
     * the stream is automatically limited to the length of the input array.
     *
     * @param input array containing ASN.1 encoded data.
     * @param lazyEvaluate true if parsing inside constructed objects can be delayed.
     */
    public ASN1InputStream(byte[] input, boolean lazyEvaluate)
    {
        this(new ByteArrayInputStream(input), input.length, lazyEvaluate);
    }

    /**
     * Create an ASN1InputStream where no DER object will be longer than limit.
     * 
     * @param input stream containing ASN.1 encoded data.
     * @param limit maximum size of a DER encoded object.
     */
    public ASN1InputStream(InputStream input, int limit)
    {
        this(input, limit, false);
    }

    /**
     * Create an ASN1InputStream where no DER object will be longer than limit, and constructed
     * objects such as sequences will be parsed lazily.
     *
     * @param input stream containing ASN.1 encoded data.
     * @param lazyEvaluate true if parsing inside constructed objects can be delayed.
     */
    public ASN1InputStream(InputStream input, boolean lazyEvaluate)
    {
        this(input, StreamUtil.findLimit(input), lazyEvaluate);
    }

    /**
     * Create an ASN1InputStream where no DER object will be longer than limit, and constructed
     * objects such as sequences will be parsed lazily.
     *
     * @param input stream containing ASN.1 encoded data.
     * @param limit maximum size of a DER encoded object.
     * @param lazyEvaluate true if parsing inside constructed objects can be delayed.
     */
    public ASN1InputStream(InputStream input, int limit, boolean lazyEvaluate)
    {
        this(input, limit, lazyEvaluate, new byte[11][]);
    }

    private ASN1InputStream(InputStream input, int limit, boolean lazyEvaluate, byte[][] tmpBuffers)
    {
        super(input);
        this.limit = limit;
        this.lazyEvaluate = lazyEvaluate;
        this.tmpBuffers = tmpBuffers;
    }

    int getLimit()
    {
        return limit;
    }

    protected int readLength()
        throws IOException
    {
        return readLength(this, limit, false);
    }

    protected void readFully(
        byte[]  bytes)
        throws IOException
    {
        if (Streams.readFully(this, bytes, 0, bytes.length) != bytes.length)
        {
            throw new EOFException("EOF encountered in middle of object");
        }
    }

    /**
     * build an object given its tag and the number of bytes to construct it from.
     *
     * @param tag the full tag details.
     * @param tagNo the tagNo defined.
     * @param length the length of the object.
     * @return the resulting primitive.
     * @throws java.io.IOException on processing exception.
     */
    protected ASN1Primitive buildObject(
        int       tag,
        int       tagNo,
        int       length)
        throws IOException
    {
        // TODO[asn1] Special-case zero length first?

        DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(this, length, limit);

        if (0 == (tag & FLAGS))
        {
            return createPrimitiveDERObject(tagNo, defIn, tmpBuffers);
        }

        int tagClass = tag & PRIVATE;
        if (0 != tagClass)
        {
            boolean isConstructed = (tag & CONSTRUCTED) != 0;
            return readTaggedObjectDL(tagClass, tagNo, isConstructed, defIn);
        }

        switch (tagNo)
        {
        case BIT_STRING:
        {
            return buildConstructedBitString(readVector(defIn));
        }
        case OCTET_STRING:
        {
            //
            // yes, people actually do this...
            //
            return buildConstructedOctetString(readVector(defIn));
        }
        case SEQUENCE:
        {
            if (defIn.getRemaining() < 1)
            {
                return DLFactory.EMPTY_SEQUENCE;
            }
            else if (lazyEvaluate)
            {
                return new LazyEncodedSequence(defIn.toByteArray());
            }
            else
            {
                return DLFactory.createSequence(readVector(defIn));
            }
        }
        case SET:
            return DLFactory.createSet(readVector(defIn));
        case EXTERNAL:
            return DLFactory.createSequence(readVector(defIn)).toASN1External();
        default:
            throw new IOException("unknown tag " + tagNo + " encountered");
        }
    }

    public ASN1Primitive readObject()
        throws IOException
    {
        int tag = read();
        if (tag <= 0)
        {
            if (tag == 0)
            {
                throw new IOException("unexpected end-of-contents marker");
            }

            return null;
        }

        int tagNo = readTagNumber(this, tag);
        int length = readLength();

        if (length >= 0)
        {
            // definite-length
            try
            {
                return buildObject(tag, tagNo, length);
            }
            catch (IllegalArgumentException e)
            {
                throw new ASN1Exception("corrupted stream detected", e);
            }
        }

        // indefinite-length

        if (0 == (tag & CONSTRUCTED))
        {
            throw new IOException("indefinite-length primitive encoding encountered");
        }

        IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(this, limit);
        ASN1StreamParser sp = new ASN1StreamParser(indIn, limit, tmpBuffers);

        int tagClass = tag & PRIVATE;
        if (0 != tagClass)
        {
            return sp.loadTaggedIL(tagClass, tagNo);
        }

        switch (tagNo)
        {
        case BIT_STRING:
            return BERBitStringParser.parse(sp);
        case OCTET_STRING:
            return BEROctetStringParser.parse(sp);
        case EXTERNAL:
            // TODO[asn1] BERExternalParser
            return DERExternalParser.parse(sp);
        case SEQUENCE:
            return BERSequenceParser.parse(sp);
        case SET:
            return BERSetParser.parse(sp);
        default:
            throw new IOException("unknown BER object encountered");
        }
    }

    ASN1BitString buildConstructedBitString(ASN1EncodableVector contentsElements) throws IOException
    {
        ASN1BitString[] strings = new ASN1BitString[contentsElements.size()];

        for (int i = 0; i != strings.length; i++)
        {
            ASN1Encodable asn1Obj = contentsElements.get(i);
            if (asn1Obj instanceof ASN1BitString)
            {
                strings[i] = (ASN1BitString)asn1Obj;
            }
            else
            {
                throw new ASN1Exception(
                    "unknown object encountered in constructed BIT STRING: " + asn1Obj.getClass());
            }
        }

        // TODO Probably ought to be DLBitString
        return new BERBitString(strings);
    }

    ASN1OctetString buildConstructedOctetString(ASN1EncodableVector contentsElements) throws IOException
    {
        ASN1OctetString[] strings = new ASN1OctetString[contentsElements.size()];

        for (int i = 0; i != strings.length; i++)
        {
            ASN1Encodable asn1Obj = contentsElements.get(i);
            if (asn1Obj instanceof ASN1OctetString)
            {
                strings[i] = (ASN1OctetString)asn1Obj;
            }
            else
            {
                throw new ASN1Exception(
                    "unknown object encountered in constructed OCTET STRING: " + asn1Obj.getClass());
            }
        }

        // TODO Probably ought to be DEROctetString (no DLOctetString available)
        return new BEROctetString(strings);
    }

    ASN1Primitive readTaggedObjectDL(int tagClass, int tagNo, boolean constructed, DefiniteLengthInputStream defIn)
        throws IOException
    {
        if (!constructed)
        {
            byte[] contentsOctets = defIn.toByteArray();
            return ASN1TaggedObject.createPrimitive(tagClass, tagNo, contentsOctets);
        }

        ASN1EncodableVector contentsElements = readVector(defIn);
        return ASN1TaggedObject.createConstructedDL(tagClass, tagNo, contentsElements);
    }

    ASN1EncodableVector readVector() throws IOException
    {
        ASN1Primitive p = readObject();
        if (null == p)
        {
            return new ASN1EncodableVector(0);
        }

        ASN1EncodableVector v = new ASN1EncodableVector();
        do
        {
            v.add(p);
        }
        while ((p = readObject()) != null);
        return v;
    }

    ASN1EncodableVector readVector(DefiniteLengthInputStream defIn) throws IOException
    {
        int remaining = defIn.getRemaining();
        if (remaining < 1)
        {
            return new ASN1EncodableVector(0);
        }

        return new ASN1InputStream(defIn, remaining, lazyEvaluate, tmpBuffers).readVector();
    }

    static int readTagNumber(InputStream s, int tag) 
        throws IOException
    {
        int tagNo = tag & 0x1f;

        //
        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        //
        if (tagNo == 0x1f)
        {
            int b = s.read();
            if (b < 31)
            {
                if (b < 0)
                {
                    throw new EOFException("EOF found inside tag value.");
                }
                throw new IOException("corrupted stream - high tag number < 31 found");
            }

            tagNo = b & 0x7f;

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if (0 == tagNo)
            {
                throw new IOException("corrupted stream - invalid high tag number found");
            }

            while ((b & 0x80) != 0)
            {
                if ((tagNo >>> 24) != 0)
                {
                    throw new IOException("Tag number more than 31 bits");
                }

                tagNo <<= 7;

                b = s.read();
                if (b < 0)
                {
                    throw new EOFException("EOF found inside tag value.");
                }

                tagNo |= (b & 0x7f);
            }
        }

        return tagNo;
    }

    static int readLength(InputStream s, int limit, boolean isParsing)
        throws IOException
    {
        int length = s.read();
        if (0 == (length >>> 7))
        {
            // definite-length short form 
            return length;
        }
        if (0x80 == length)
        {
            // indefinite-length
            return -1;
        }
        if (length < 0)
        {
            throw new EOFException("EOF found when length expected");
        }
        if (0xFF == length)
        {
            throw new IOException("invalid long form definite-length 0xFF");
        }

        int octetsCount = length & 0x7F, octetsPos = 0;

        length = 0;
        do
        {
            int octet = s.read();
            if (octet < 0)
            {
                throw new EOFException("EOF found reading length");
            }

            if ((length >>> 23) != 0)
            {
                throw new IOException("long form definite-length more than 31 bits");
            }

            length = (length << 8) + octet;
        }
        while (++octetsPos < octetsCount);

        if (length >= limit && !isParsing)   // after all we must have read at least 1 byte
        {
            throw new IOException("corrupted stream - out of bounds length found: " + length + " >= " + limit);
        }

        return length;
    }

    private static byte[] getBuffer(DefiniteLengthInputStream defIn, byte[][] tmpBuffers)
        throws IOException
    {
        int len = defIn.getRemaining();
        if (len >= tmpBuffers.length)
        {
            return defIn.toByteArray();
        }

        byte[] buf = tmpBuffers[len];
        if (buf == null)
        {
            buf = tmpBuffers[len] = new byte[len];
        }

        defIn.readAllIntoByteArray(buf);

        return buf;
    }

    private static char[] getBMPCharBuffer(DefiniteLengthInputStream defIn)
        throws IOException
    {
        int remainingBytes = defIn.getRemaining();
        if (0 != (remainingBytes & 1))
        {
            throw new IOException("malformed BMPString encoding encountered");
        }

        char[] string = new char[remainingBytes / 2];
        int stringPos = 0;

        byte[] buf = new byte[8];
        while (remainingBytes >= 8)
        {
            if (Streams.readFully(defIn, buf, 0, 8) != 8)
            {
                throw new EOFException("EOF encountered in middle of BMPString");
            }

            string[stringPos    ] = (char)((buf[0] << 8) | (buf[1] & 0xFF));
            string[stringPos + 1] = (char)((buf[2] << 8) | (buf[3] & 0xFF));
            string[stringPos + 2] = (char)((buf[4] << 8) | (buf[5] & 0xFF));
            string[stringPos + 3] = (char)((buf[6] << 8) | (buf[7] & 0xFF));
            stringPos += 4;
            remainingBytes -= 8;
        }
        if (remainingBytes > 0)
        {
            if (Streams.readFully(defIn, buf, 0, remainingBytes) != remainingBytes)
            {
                throw new EOFException("EOF encountered in middle of BMPString");
            }

            int bufPos = 0;
            do
            {
                int b1 = buf[bufPos++] << 8;
                int b2 = buf[bufPos++] & 0xFF;
                string[stringPos++] = (char)(b1 | b2);
            }
            while (bufPos < remainingBytes);
        }

        if (0 != defIn.getRemaining() || string.length != stringPos)
        {
            throw new IllegalStateException();
        }

        return string;
    }

    static ASN1Primitive createPrimitiveDERObject(
        int     tagNo,
        DefiniteLengthInputStream defIn,
        byte[][] tmpBuffers)
        throws IOException
    {
        /*
         * TODO[asn1] Lookup the universal type object and get it to parse the stream directly (possibly with
         * access to a single temporary buffer replacing tmpBuffers).
         */
        try
        {
            switch (tagNo)
            {
            case BIT_STRING:
                return ASN1BitString.createPrimitive(defIn.toByteArray());
            case BMP_STRING:
                return ASN1BMPString.createPrimitive(getBMPCharBuffer(defIn));
            case BOOLEAN:
                return ASN1Boolean.createPrimitive(getBuffer(defIn, tmpBuffers));
            case ENUMERATED:
                // TODO Ideally only clone if we used a buffer
                return ASN1Enumerated.createPrimitive(getBuffer(defIn, tmpBuffers), true);
            case GENERAL_STRING:
                return ASN1GeneralString.createPrimitive(defIn.toByteArray());
            case GENERALIZED_TIME:
                return ASN1GeneralizedTime.createPrimitive(defIn.toByteArray());
            case GRAPHIC_STRING:
                return ASN1GraphicString.createPrimitive(defIn.toByteArray());
            case IA5_STRING:
                return ASN1IA5String.createPrimitive(defIn.toByteArray());
            case INTEGER:
                return ASN1Integer.createPrimitive(defIn.toByteArray());
            case NULL:
                return ASN1Null.createPrimitive(defIn.toByteArray());
            case NUMERIC_STRING:
                return ASN1NumericString.createPrimitive(defIn.toByteArray());
            case OBJECT_DESCRIPTOR:
                return ASN1ObjectDescriptor.createPrimitive(defIn.toByteArray());
            case OBJECT_IDENTIFIER:
                // TODO Ideally only clone if we used a buffer
                return ASN1ObjectIdentifier.createPrimitive(getBuffer(defIn, tmpBuffers), true);
            case OCTET_STRING:
                return ASN1OctetString.createPrimitive(defIn.toByteArray());
            case PRINTABLE_STRING:
                return ASN1PrintableString.createPrimitive(defIn.toByteArray());
            case RELATIVE_OID:
                return ASN1RelativeOID.createPrimitive(defIn.toByteArray(), false);
            case T61_STRING:
                return ASN1T61String.createPrimitive(defIn.toByteArray());
            case UNIVERSAL_STRING:
                return ASN1UniversalString.createPrimitive(defIn.toByteArray());
            case UTC_TIME:
                return ASN1UTCTime.createPrimitive(defIn.toByteArray());
            case UTF8_STRING:
                return ASN1UTF8String.createPrimitive(defIn.toByteArray());
            case VIDEOTEX_STRING:
                return ASN1VideotexString.createPrimitive(defIn.toByteArray());
            case VISIBLE_STRING:
                return ASN1VisibleString.createPrimitive(defIn.toByteArray());
            case TIME:
            case DATE:
            case TIME_OF_DAY:
            case DATE_TIME:
            case DURATION:
            case OBJECT_IDENTIFIER_IRI:
            case RELATIVE_OID_IRI:
                throw new IOException("unsupported tag " + tagNo + " encountered");
            default:
                throw new IOException("unknown tag " + tagNo + " encountered");
            }
        }
        catch (IllegalArgumentException e)
        {
            throw new ASN1Exception(e.getMessage(), e);
        }
        catch (IllegalStateException e)
        {
            throw new ASN1Exception(e.getMessage(), e);
        }
    }
}
