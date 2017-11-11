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



/**
 * Parser for indefinite-length tagged objects.
 */
public class BERTaggedObjectParser
    implements ASN1TaggedObjectParser
{
    private final boolean _constructed;
    private final int _tagNumber;
    private final ASN1StreamParser _parser;

    BERTaggedObjectParser(
        final boolean             constructed,
        final int                 tagNumber,
        final ASN1StreamParser    parser)
    {
        _constructed = constructed;
        _tagNumber = tagNumber;
        _parser = parser;
    }

    /**
     * Return true if this tagged object is marked as constructed.
     *
     * @return true if constructed, false otherwise.
     */
    public boolean isConstructed()
    {
        return _constructed;
    }

    /**
     * Return the tag number associated with this object.
     *
     * @return the tag number.
     */
    @Override
    public int getTagNo()
    {
        return _tagNumber;
    }

    /**
     * Return an object parser for the contents of this tagged object.
     *
     * @param tag the actual tag number of the object (needed if implicit).
     * @param isExplicit true if the contained object was explicitly tagged, false if implicit.
     * @return an ASN.1 encodable object parser.
     * @throws IOException if there is an issue building the object parser from the stream.
     */
    @Override
    public ASN1Encodable getObjectParser(
        final int     tag,
        final boolean isExplicit)
    {
        if (isExplicit)
        {
            if (!_constructed)
            {
                throw new ASN1Exception("Explicit tags must be constructed (see X.690 8.14.2)");
            }
            return _parser.readObject();
        }

        return _parser.readImplicit(_constructed, tag);
    }

    /**
     * Return an in-memory, encodable, representation of the tagged object.
     *
     * @return an ASN1TaggedObject.
     * @throws IOException if there is an issue loading the data.
     */
    @Override
    public ASN1Primitive getLoadedObject()
    {
        return _parser.readTaggedObject(_constructed, _tagNumber);
    }

    /**
     * Return an ASN1TaggedObject representing this parser and its contents.
     *
     * @return an ASN1TaggedObject
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
            return getLoadedObject();
     }
}
