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


import static com.github.gv2011.util.ex.Exceptions.call;

import java.io.InputStream;

import com.github.gv2011.util.bytes.Bytes;

/**
 * TODO: Does not close streams properly. See @SuppressWarnings("resource").
 *
 * A parser for ASN.1 streams which also returns, where possible, parsers for the objects it encounters.
 */
public class ASN1StreamParser implements ASN1Parser{
    private final InputStream _in;
    private final int         _limit;
    private final byte[][] tmpBuffers;

    public ASN1StreamParser(
        final InputStream in)
    {
        this(in, StreamUtil.findLimit(in));
    }

    public ASN1StreamParser(
        final InputStream in,
        final int         limit)
    {
        _in = in;
        _limit = limit;

        tmpBuffers = new byte[11][];
    }

    public ASN1StreamParser(
        final Bytes encoding)
    {
        this(encoding.openStream(), encoding.size());
    }

    ASN1Encodable readIndef(final int tagValue)
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

    ASN1Encodable readImplicit(final boolean constructed, final int tag)
    {
        if (_in instanceof IndefiniteLengthInputStream)
        {
            if (!constructed)
            {
                throw new ASN1Exception("indefinite-length primitive encoding encountered");
            }

            return readIndef(tag);
        }

        if (constructed)
        {
            switch (tag)
            {
                case BERTags.SET:
                    return new DERSetParser(this);
                case BERTags.SEQUENCE:
                    return new DERSequenceParser(this);
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

    ASN1Primitive readTaggedObject(final boolean constructed, final int tag)
    {
        if (!constructed)
        {
            // Note: !CONSTRUCTED => IMPLICIT
            final DefiniteLengthInputStream defIn = (DefiniteLengthInputStream)_in;
            return new DERTaggedObject(false, tag, new DEROctetString(defIn.toByteArray()));
        }

        final ASN1EncodableVector v = readVector();

        if (_in instanceof IndefiniteLengthInputStream)
        {
            return v.size() == 1
                ?   new BERTaggedObject(true, tag, v.get(0))
                :   new BERTaggedObject(false, tag, BERFactory.createSequence(v));
        }

        return v.size() == 1
            ?   new DERTaggedObject(true, tag, v.get(0))
            :   new DERTaggedObject(false, tag, DERFactory.createSequence(v));
    }

    @Override
    @SuppressWarnings("resource")
    public ASN1Encodable readObject(){
        final int tag = call(_in::read);
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
        final int tagNo = ASN1InputStream.readTagNumber(_in, tag);

        final boolean isConstructed = (tag & BERTags.CONSTRUCTED) != 0;

        //
        // calculate length
        //
        final int length = ASN1InputStream.readLength(_in, _limit);

        if (length < 0) // indefinite-length method
        {
            if (!isConstructed)
            {
                throw new ASN1Exception("indefinite-length primitive encoding encountered");
            }

            final IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(_in, _limit);
            final ASN1StreamParser sp = new ASN1StreamParser(indIn, _limit);

            if ((tag & BERTags.APPLICATION) != 0)
            {
                return new BERApplicationSpecificParser(tagNo, sp);
            }

            if ((tag & BERTags.TAGGED) != 0)
            {
                return new BERTaggedObjectParser(true, tagNo, sp);
            }

            return sp.readIndef(tagNo);
        }
        else
        {
            final DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(_in, length);

            if ((tag & BERTags.APPLICATION) != 0)
            {
                return new DERApplicationSpecific(isConstructed, tagNo, defIn.toByteArray());
            }

            if ((tag & BERTags.TAGGED) != 0)
            {
                return new BERTaggedObjectParser(isConstructed, tagNo, new ASN1StreamParser(defIn));
            }

            if (isConstructed)
            {
                // TODO There are other tags that may be constructed (e.g. BIT_STRING)
                switch (tagNo)
                {
                    case BERTags.OCTET_STRING:
                        //
                        // yes, people actually do this...
                        //
                        return new BEROctetStringParser(new ASN1StreamParser(defIn));
                    case BERTags.SEQUENCE:
                        return new DERSequenceParser(new ASN1StreamParser(defIn));
                    case BERTags.SET:
                        return new DERSetParser(new ASN1StreamParser(defIn));
                    case BERTags.EXTERNAL:
                        return new DERExternalParser(new ASN1StreamParser(defIn));
                    default:
                        throw new ASN1ParsingException("unknown tag " + tagNo + " encountered");
                }
            }

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
            catch (final IllegalArgumentException e)
            {
                throw new ASN1ParsingException("corrupted stream detected", e);
            }
        }
    }

    private void set00Check(final boolean enabled)
    {
        if (_in instanceof IndefiniteLengthInputStream)
        {
            ((IndefiniteLengthInputStream)_in).setEofOn00(enabled);
        }
    }

    ASN1EncodableVector readVector(){
        final ASN1EncodableVector v = new ASN1EncodableVector();

        ASN1Encodable obj;
        while ((obj = readObject()) != null)
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

        return v;
    }
}
