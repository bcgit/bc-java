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


import static com.github.gv2011.util.bytes.ByteUtils.emptyBytes;

import com.github.gv2011.util.bytes.Bytes;

/**
 * DER TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public class DERTaggedObject
    extends ASN1TaggedObject
{
    private static final Bytes ZERO_BYTES = emptyBytes();

    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public DERTaggedObject(
        final boolean       explicit,
        final int           tagNo,
        final ASN1Encodable obj)
    {
        super(explicit, tagNo, obj);
    }

    public DERTaggedObject(final int tagNo, final ASN1Encodable encodable)
    {
        super(true, tagNo, encodable);
    }

    @Override
    boolean isConstructed()
    {
        if (!empty)
        {
            if (explicit)
            {
                return true;
            }
            else
            {
                final ASN1Primitive primitive = obj.toASN1Primitive().toDERObject();

                return primitive.isConstructed();
            }
        }
        else
        {
            return true;
        }
    }

    @Override
    int encodedLength()
    {
        if (!empty)
        {
            final ASN1Primitive primitive = obj.toASN1Primitive().toDERObject();
            int length = primitive.encodedLength();

            if (explicit)
            {
                return StreamUtil.calculateTagLength(tagNo) + StreamUtil.calculateBodyLength(length) + length;
            }
            else
            {
                // header length already in calculation
                length = length - 1;

                return StreamUtil.calculateTagLength(tagNo) + length;
            }
        }
        else
        {
            return StreamUtil.calculateTagLength(tagNo) + 1;
        }
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        if (!empty)
        {
            final ASN1Primitive primitive = obj.toASN1Primitive().toDERObject();

            if (explicit)
            {
                out.writeTag(BERTags.CONSTRUCTED | BERTags.TAGGED, tagNo);
                out.writeLength(primitive.encodedLength());
                out.writeObject(primitive);
            }
            else
            {
                //
                // need to mark constructed types...
                //
                int flags;
                if (primitive.isConstructed())
                {
                    flags = BERTags.CONSTRUCTED | BERTags.TAGGED;
                }
                else
                {
                    flags = BERTags.TAGGED;
                }

                out.writeTag(flags, tagNo);
                out.writeImplicitObject(primitive);
            }
        }
        else
        {
            out.writeEncoded(BERTags.CONSTRUCTED | BERTags.TAGGED, tagNo, ZERO_BYTES);
        }
    }
}
