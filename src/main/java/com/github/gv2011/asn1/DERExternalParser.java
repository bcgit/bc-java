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
 * Parser DER EXTERNAL tagged objects.
 */
public class DERExternalParser
    implements ASN1Encodable, InMemoryRepresentable
{
    private final ASN1StreamParser _parser;

    /**
     * Base constructor.
     *
     * @param parser the underlying parser to read the DER EXTERNAL from.
     */
    public DERExternalParser(final ASN1StreamParser parser)
    {
        _parser = parser;
    }

    public ASN1Encodable readObject()
    {
        return _parser.readObject();
    }

    /**
     * Return an in-memory, encodable, representation of the EXTERNAL object.
     *
     * @return a DERExternal.
     * @throws IOException if there is an issue loading the data.
     */
    @Override
    public ASN1Primitive getLoadedObject()
    {
        try
        {
            return new DERExternal(_parser.readVector());
        }
        catch (final IllegalArgumentException e)
        {
            throw new ASN1Exception(e.getMessage(), e);
        }
    }

    /**
     * Return an DERExternal representing this parser and its contents.
     *
     * @return an DERExternal
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (final IllegalArgumentException ioe)
        {
            throw new ASN1ParsingException("unable to get DER object", ioe);
        }
    }
}
