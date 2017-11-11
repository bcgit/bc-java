package com.github.gv2011.asn1;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


import static com.github.gv2011.util.Verify.verifyEqual;
import static com.github.gv2011.util.bytes.ByteUtils.newBytes;
import static com.github.gv2011.util.ex.Exceptions.call;

import java.io.FilterInputStream;
import java.io.InputStream;

import com.github.gv2011.asn1.util.io.Streams;
import com.github.gv2011.util.bytes.Bytes;

/**
 * a general purpose ASN.1 decoder - note: this class differs from the
 * others in that it returns null after it has read the last object in
 * the stream. If an ASN.1 NULL is encountered a DER/BER Null object is
 * returned.
 */
public class ASN1InputStream
    extends FilterInputStream
    implements BERTags, ASN1Parser
{
    private final int limit;
    private final boolean lazyEvaluate;

    private final byte[][] tmpBuffers;

    public static ASN1Primitive parse(final Bytes asn1) {
      @SuppressWarnings("resource")
      final ASN1InputStream asn1InputStream = new ASN1InputStream(asn1);
      final ASN1Primitive result = asn1InputStream.readObject();
      verifyEqual(asn1InputStream.readObject(), null);
      return result;
    }

    public ASN1InputStream(
        final InputStream is)
    {
        this(is, StreamUtil.findLimit(is));
    }

    /**
     * Create an ASN1InputStream based on the input byte array. The length of DER objects in
     * the stream is automatically limited to the length of the input array.
     *
     * @param input array containing ASN.1 encoded data.
     */
    public ASN1InputStream(
        final Bytes input)
    {
        this(input.openStream(), input.size());
    }

    /**
     * Create an ASN1InputStream based on the input byte array. The length of DER objects in
     * the stream is automatically limited to the length of the input array.
     *
     * @param input array containing ASN.1 encoded data.
     * @param lazyEvaluate true if parsing inside constructed objects can be delayed.
     */
    public ASN1InputStream(
        final Bytes input,
        final boolean lazyEvaluate)
    {
        this(input.openStream(), input.size(), lazyEvaluate);
    }

    /**
     * Create an ASN1InputStream where no DER object will be longer than limit.
     *
     * @param input stream containing ASN.1 encoded data.
     * @param limit maximum size of a DER encoded object.
     */
    public ASN1InputStream(
        final InputStream input,
        final int         limit)
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
    public ASN1InputStream(
        final InputStream input,
        final boolean     lazyEvaluate)
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
    public ASN1InputStream(
        final InputStream input,
        final int         limit,
        final boolean     lazyEvaluate)
    {
        super(input);
        this.limit = limit;
        this.lazyEvaluate = lazyEvaluate;
        tmpBuffers = new byte[11][];
    }

    int getLimit()
    {
        return limit;
    }

    protected int readLength(){
        return readLength(this, limit);
    }

    protected void readFully(
        final byte[]  bytes){
        if (Streams.readFully(this, bytes) != bytes.length)
        {
            throw new ASN1ParsingException("EOF encountered in middle of object");
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
    @SuppressWarnings("resource")
    protected ASN1Primitive buildObject(
        final int       tag,
        final int       tagNo,
        final int       length
    ){
        final boolean isConstructed = (tag & CONSTRUCTED) != 0;

        final DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(this, length);

        if ((tag & APPLICATION) != 0)
        {
            return new DERApplicationSpecific(isConstructed, tagNo, defIn.toByteArray());
        }

        if ((tag & TAGGED) != 0)
        {
            return new ASN1StreamParser(defIn).readTaggedObject(isConstructed, tagNo);
        }

        if (isConstructed)
        {
            // TODO There are other tags that may be constructed (e.g. BIT_STRING)
            switch (tagNo)
            {
                case OCTET_STRING:
                    //
                    // yes, people actually do this...
                    //
                    final ASN1EncodableVector v = buildDEREncodableVector(defIn);
                    final ASN1OctetString[] strings = new ASN1OctetString[v.size()];

                    for (int i = 0; i != strings.length; i++)
                    {
                        strings[i] = (ASN1OctetString)v.get(i);
                    }

                    return new BEROctetString(strings);
                case SEQUENCE:
                    if (lazyEvaluate)
                    {
                        return new LazyEncodedSequence(defIn.toByteArray());
                    }
                    else
                    {
                        return DERFactory.createSequence(buildDEREncodableVector(defIn));
                    }
                case SET:
                    return DERFactory.createSet(buildDEREncodableVector(defIn));
                case EXTERNAL:
                    return new DERExternal(buildDEREncodableVector(defIn));
                default:
                    throw new ASN1ParsingException("unknown tag " + tagNo + " encountered");
            }
        }

        return createPrimitiveDERObject(tagNo, defIn, tmpBuffers);
    }

    ASN1EncodableVector buildEncodableVector(){
        final ASN1EncodableVector v = new ASN1EncodableVector();
        ASN1Primitive o;

        while ((o = readObject()) != null)
        {
            v.add(o);
        }

        return v;
    }

    @SuppressWarnings("resource")
    ASN1EncodableVector buildDEREncodableVector(
        final DefiniteLengthInputStream dIn){
        return new ASN1InputStream(dIn).buildEncodableVector();
    }

    @Override
    public ASN1Primitive readObject(){
        final int tag = call(this::read);
        if (tag <= 0)
        {
            if (tag == 0)
            {
                throw new ASN1ParsingException("unexpected end-of-contents marker");
            }

            return null;
        }

        //
        // calculate tag number
        //
        final int tagNo = readTagNumber(this, tag);

        final boolean isConstructed = (tag & CONSTRUCTED) != 0;

        //
        // calculate length
        //
        final int length = readLength();

        if (length < 0) // indefinite-length method
        {
            if (!isConstructed)
            {
                throw new ASN1ParsingException("indefinite-length primitive encoding encountered");
            }

            final IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(this, limit);
            final ASN1StreamParser sp = new ASN1StreamParser(indIn, limit);

            if ((tag & APPLICATION) != 0)
            {
                return new BERApplicationSpecificParser(tagNo, sp).getLoadedObject();
            }

            if ((tag & TAGGED) != 0)
            {
                return new BERTaggedObjectParser(true, tagNo, sp).getLoadedObject();
            }

            // TODO There are other tags that may be constructed (e.g. BIT_STRING)
            switch (tagNo)
            {
                case OCTET_STRING:
                    return new BEROctetStringParser(sp).getLoadedObject();
                case SEQUENCE:
                    return new BERSequenceParser(sp).getLoadedObject();
                case SET:
                    return new BERSetParser(sp).getLoadedObject();
                case EXTERNAL:
                    return new DERExternalParser(sp).getLoadedObject();
                default:
                    throw new ASN1ParsingException("unknown BER object encountered");
            }
        }
        else
        {
            try
            {
                return buildObject(tag, tagNo, length);
            }
            catch (final IllegalArgumentException e)
            {
                throw new ASN1ParsingException("corrupted stream detected", e);
            }
        }
    }

    static int readTagNumber(final InputStream s, final int tag){
        int tagNo = tag & 0x1f;

        //
        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        //
        if (tagNo == 0x1f)
        {
            tagNo = 0;

            int b = call(s::read);

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if ((b & 0x7f) == 0) // Note: -1 will pass
            {
                throw new ASN1ParsingException("corrupted stream - invalid high tag number found");
            }

            while ((b >= 0) && ((b & 0x80) != 0))
            {
                tagNo |= (b & 0x7f);
                tagNo <<= 7;
                b = call(s::read);
            }

            if (b < 0)
            {
                throw new ASN1ParsingException("EOF found inside tag value.");
            }

            tagNo |= (b & 0x7f);
        }

        return tagNo;
    }

    static int readLength(final InputStream s, final int limit){
        int length = call(s::read);
        if (length < 0)
        {
            throw new ASN1ParsingException("EOF found when length expected");
        }

        if (length == 0x80)
        {
            return -1;      // indefinite-length encoding
        }

        if (length > 127)
        {
            final int size = length & 0x7f;

            // Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be caught here
            if (size > 4)
            {
                throw new ASN1ParsingException("DER length more than 4 bytes: " + size);
            }

            length = 0;
            for (int i = 0; i < size; i++)
            {
                final int next = call(s::read);

                if (next < 0)
                {
                    throw new ASN1ParsingException("EOF found reading length");
                }

                length = (length << 8) + next;
            }

            if (length < 0)
            {
                throw new ASN1ParsingException("corrupted stream - negative length found");
            }

            if (length >= limit)   // after all we must have read at least 1 byte
            {
                throw new ASN1ParsingException("corrupted stream - out of bounds length found");
            }
        }

        return length;
    }

    private static Bytes getBuffer(final DefiniteLengthInputStream defIn, final byte[][] tmpBuffers){
        final int len = defIn.getRemaining();
        if (defIn.getRemaining() < tmpBuffers.length)
        {
            byte[] buf = tmpBuffers[len];

            if (buf == null)
            {
                buf = tmpBuffers[len] = new byte[len];
            }

            Streams.readFully(defIn, buf);

            return newBytes(buf);
        }
        else
        {
            return defIn.toByteArray();
        }
    }

    private static char[] getBMPCharBuffer(final DefiniteLengthInputStream defIn){
        final int len = defIn.getRemaining() / 2;
        final char[] buf = new char[len];
        int totalRead = 0;
        while (totalRead < len)
        {
            final int ch1 = call(defIn::read);
            if (ch1 < 0)
            {
                break;
            }
            final int ch2 = call(defIn::read);
            if (ch2 < 0)
            {
                break;
            }
            buf[totalRead++] = (char)((ch1 << 8) | (ch2 & 0xff));
        }

        return buf;
    }

    static ASN1Primitive createPrimitiveDERObject(
        final int     tagNo,
        final DefiniteLengthInputStream defIn,
        final byte[][] tmpBuffers){
        switch (tagNo)
        {
            case BIT_STRING:
                return ASN1BitString.fromInputStream(defIn.getRemaining(), defIn);
            case BMP_STRING:
                return new DERBMPString(getBMPCharBuffer(defIn));
            case BOOLEAN:
                return ASN1Boolean.fromOctetString(getBuffer(defIn, tmpBuffers));
            case ENUMERATED:
                return ASN1Enumerated.fromOctetString(getBuffer(defIn, tmpBuffers));
            case GENERALIZED_TIME:
                return new ASN1GeneralizedTime(defIn.toByteArray());
            case GENERAL_STRING:
                return new DERGeneralString(defIn.toByteArray());
            case IA5_STRING:
                return new DERIA5String(defIn.toByteArray());
            case INTEGER:
                return new ASN1Integer(defIn.toByteArray());
            case NULL:
                return DERNull.INSTANCE;   // actual content is ignored (enforce 0 length?)
            case NUMERIC_STRING:
                return new DERNumericString(defIn.toByteArray());
            case OBJECT_IDENTIFIER:
                return ASN1ObjectIdentifier.fromOctetString(getBuffer(defIn, tmpBuffers));
            case OCTET_STRING:
                return new DEROctetString(defIn.toByteArray());
            case PRINTABLE_STRING:
                return new DERPrintableString(defIn.toByteArray());
            case T61_STRING:
                return new DERT61String(defIn.toByteArray());
            case UNIVERSAL_STRING:
                return new DERUniversalString(defIn.toByteArray());
            case UTC_TIME:
                return new ASN1UTCTime(defIn.toByteArray());
            case UTF8_STRING:
                return new DERUTF8String(defIn.toByteArray());
            case VISIBLE_STRING:
                return new DERVisibleString(defIn.toByteArray());
            case GRAPHIC_STRING:
                return new DERGraphicString(defIn.toByteArray());
            case VIDEOTEX_STRING:
                return new DERVideotexString(defIn.toByteArray());
            default:
                throw new ASN1ParsingException("unknown tag " + tagNo + " encountered");
        }
    }
}
