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



import java.io.InputStream;

/**
 * Parse for DER encoded OCTET STRINGS
 */
public class DEROctetStringParser
    implements ASN1OctetStringParser
{
    private final DefiniteLengthInputStream stream;

    DEROctetStringParser(
        final DefiniteLengthInputStream stream)
    {
        this.stream = stream;
    }

    /**
     * Return an InputStream representing the contents of the OCTET STRING.
     *
     * @return an InputStream with its source as the OCTET STRING content.
     */
    @Override
    public InputStream getOctetStream()
    {
        return stream;
    }

    /**
     * Return an in-memory, encodable, representation of the OCTET STRING.
     *
     * @return a DEROctetString.
     * @throws IOException if there is an issue loading the data.
     */
    @Override
    public ASN1Primitive getLoadedObject()
    {
        return new DEROctetString(stream.toByteArray());
    }

    /**
     * Return an DEROctetString representing this parser and its contents.
     *
     * @return an DEROctetString
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
            return getLoadedObject();
    }
}
